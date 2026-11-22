# Network Analysis of AI-Enabled Cyberattacks

Exploratory DATA 620 side project (not an assigned course deliverable). Companion to the DATA 607 project `Extra/AI_Attacks_Fortune500` in athomsonsps/DATA607.

**Notebook:** [`DATA620_AI_Attack_Network.ipynb`](DATA620_AI_Attack_Network.ipynb) (executed, outputs saved)

## Question

Which Fortune 500 companies are being attacked by people using AI? Public incident data can't answer that, because victims are rarely named (0 of 843 incidents named a Fortune 500 victim). So this project builds networks from what the data does record: the AI products named in incidents, the attack types, and MITRE ATLAS techniques.

## Networks

| Network | Nodes | Edges | Key measures |
| --- | --- | --- | --- |
| Two-mode | 12 AI products, 18 attack types | 59, weighted by incidents, tagged by AI role | degree, weighted degree |
| Projection onto AI products | 12 | 49, weighted by shared attack types | density, edge weights |
| ATLAS co-occurrence (without AML.T0115) | 34 parent techniques | 252, weighted by shared incidents | strength, betweenness, eigenvector, Louvain communities |

## Main results

- Where an incident names an AI product, 102 of 147 links (69%) are attacks **on** the product, 25 (17%) are AI used **as a weapon**, and 20 (14%) are unclear.
- ChatGPT/OpenAI has the most links (59) and the most weapon links (14).
- `AML.T0115` (*Publish Poisoned AI Artifacts*) is tagged on 500 of the 843 incidents, mostly deepfake scams, which doesn't fit. Removing it changes the top technique from *External Harms* (strength 1,186) to *LLM Data Leakage* (714).
- Louvain communities are weak (modularity 0.111).

## Data

| Source | License | In git? |
| --- | --- | --- |
| GenAI & Agentic AI Security Incidents v2.13.0 ([Hugging Face](https://huggingface.co/datasets/emmanuelgjr/genai-incidents), [PyPI](https://pypi.org/project/genai-incidents/)) | CC BY 4.0 | Derived table only: `data/ai_attack_incidents.csv` |
| [MITRE ATLAS](https://github.com/mitre-atlas/atlas-data) release 2026.09 (the release the dataset maps to) | Apache 2.0 | Derived table only: `data/atlas_2026_09_techniques.csv` |

## How to run

```bash
python3 code/prepare_data.py    # downloads into data/raw/ (not in git) and rebuilds data/*.csv
jupyter nbconvert --to notebook --execute --inplace DATA620_AI_Attack_Network.ipynb
```

Needs: `networkx`, `pandas`, `matplotlib`, `pyyaml`, `jupyter`. Tested with NetworkX 3.7, pandas 3.0.5, Matplotlib 3.11.2, Python 3.13.

## Limits

- ATLAS tags come from the dataset's automated mapper; the dataset has not published a precision figure for them. Centrality describes how tags cluster in public reporting, not how attackers operate.
- The AI role (weapon vs attacked) is assigned from the attack type, not by reading each incident.
- The AI-attack filter is keyword-based. In a spot check of 20 incidents, about 14 were real AI-enabled attacks.
- Only 134 of 843 incidents name an AI product.
- Products that get more news coverage will look more central.

## Files

- `DATA620_AI_Attack_Network.ipynb`: the analysis
- `code/prepare_data.py`: download and build the input tables
- `data/`: the two input tables
- `output/`: the three figures
