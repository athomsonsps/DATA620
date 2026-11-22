"""Build the two input tables for the network notebook.

Downloads (into data/raw/, not committed):
  - genai-incidents 2.13.0 from PyPI (CC BY 4.0)
  - MITRE ATLAS data from github.com/mitre-atlas/atlas-data (Apache 2.0)
Writes:
  - data/ai_attack_incidents.csv   one row per AI-enabled attack incident
  - data/atlas_2026_09_techniques.csv   ATLAS technique id -> name (release the dataset maps to)
"""
import csv, glob, json, os, re, subprocess, sys, zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data", "raw")
os.makedirs(RAW, exist_ok=True)

# ---- 1. download ----
if not glob.glob(os.path.join(RAW, "genai_incidents-2.13.0*.whl")):
    subprocess.run([sys.executable, "-m", "pip", "download", "--no-deps", "-q",
                    "genai-incidents==2.13.0", "-d", RAW], check=True)
atlas_dir = os.path.join(RAW, "atlas-data")
if not os.path.isdir(atlas_dir):
    subprocess.run(["git", "clone", "-q", "--depth", "1",
                    "https://github.com/mitre-atlas/atlas-data.git", atlas_dir], check=True)

whl = glob.glob(os.path.join(RAW, "genai_incidents-2.13.0*.whl"))[0]
with zipfile.ZipFile(whl) as z:
    incidents = json.loads(z.read("genai_incidents/data/incidents.min.json"))["incidents"]

# ---- 2. ATLAS names: the dataset says it maps to ATLAS 2026.09 ----
import yaml  # pyyaml
A = yaml.safe_load(open(os.path.join(atlas_dir, "dist", "v6", "ATLAS-2026.09.yaml")))
with open(os.path.join(ROOT, "data", "atlas_2026_09_techniques.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["technique_id", "name", "parent_id", "parent_name"])
    for tid, t in sorted(A["techniques"].items()):
        parent = tid.split(".")[0] + "." + tid.split(".")[1]
        w.writerow([tid, t["name"], parent, A["techniques"].get(parent, {}).get("name", "")])

# ---- 3. keep AI-as-a-tool attacks (same rule as the DATA 607 project) ----
AI = re.compile(r"\b(ai[- ](powered|driven|generated|assisted|enabled|orchestrated|based|agent)s?|using ai|used ai|with ai|llms?|large language model|chatgpt|gpt-?\d|claude|gemini|copilot|deepfakes?|voice[- ]clon\w*|cloned voice|wormgpt|fraudgpt|agentic|generative ai|genai|artificial intelligence)\b", re.I)
INTRUSION = re.compile(r"\b(phish\w*|malware|ransomware|hack\w*|breach\w*|intrusion|exfiltrat\w*|espionage|cyber[- ]?attack\w*|credential\w*|ddos|exploit\w*|backdoor\w*|infostealer|extort\w*|compromis\w*)\b", re.I)
FRAUD = re.compile(r"\b(scam\w*|fraud\w*|impersonat\w*|social engineering|wire transfer|swindl\w*)\b", re.I)

# Named AI products. A name can appear because the product was the weapon OR the target.
TOOLS = {
    "ChatGPT/OpenAI": r"chatgpt|openai|gpt-?[345o]|\bsora\b|dall-?e",
    "Claude": r"\bclaude\b|anthropic",
    "Gemini": r"gemini|\bbard\b|\bveo\s?\d?\b",
    "Copilot": r"copilot",
    "Llama/Meta AI": r"\bllama\b|meta ai",
    "DeepSeek": r"deepseek",
    "Dark-web LLMs": r"wormgpt|fraudgpt|darkgpt|wolfgpt|xanthorox|evil-?gpt|blackhatgpt|ghostgpt|kawaiigpt",
    "Cursor": r"\bcursor\b",
    "Perplexity": r"perplexity",
    "Voice/video generators": r"elevenlabs|heygen",
    "Image generators": r"midjourney|stable diffusion",
    "Mistral": r"\bmistral\b",
}
# Attack types where the AI product itself is attacked vs. used as the weapon.
TARGET = {"prompt-injection", "indirect-prompt-injection", "data-exfiltration", "jailbreak",
          "memory-poisoning", "agent-hijack", "tool-abuse", "model-poisoning", "adversarial-input",
          "rce", "auth-bypass", "supply-chain", "backdoor"}
WEAPON = {"deepfake", "phishing", "malware", "misinformation"}

rows = []
for x in incidents:
    if x.get("cve_ids") or x.get("status") == "retracted":
        continue
    text = f"{x.get('title','')} {x.get('description','')}"
    if not AI.search(text):
        continue
    intr, fraud = bool(INTRUSION.search(text)), bool(FRAUD.search(text))
    if not (intr or fraud):
        continue
    av = x.get("attack_vector") or "other"
    tools = [k for k, p in TOOLS.items() if re.search(p, text, re.I)]
    rows.append({
        "id": x["id"], "year": x.get("year"),
        "incident_type": "intrusion" if intr else "fraud/impersonation",
        "attack_vector": av,
        "ai_role": "AI product attacked" if av in TARGET else ("AI used as weapon" if av in WEAPON else "unclear"),
        "named_ai_tools": ";".join(tools),
        "atlas_techniques": ";".join(x.get("mitre_atlas") or []),
        "severity": x.get("severity"), "title": x.get("title"),
    })

with open(os.path.join(ROOT, "data", "ai_attack_incidents.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
print(f"{len(incidents)} incidents in source -> {len(rows)} AI-enabled attack incidents")
print(f"{sum(1 for r in rows if r['named_ai_tools'])} name at least one AI product")
