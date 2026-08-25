# SSH Honeypot with Attack Profiling

A low-interaction SSH honeypot designed to capture live credential-stuffing traffic, extract authentication metadata, profile attacker behavior via machine learning, and visualize threat origins on an interactive map.

## Key Features

* **Low-Interaction Honeypot**: Built using custom `Paramiko` server sockets listening on port `2222` to capture live payload metrics without exposing underlying shell access.
* **Attacker Profiling Engine**: Utilizes `Scikit-learn` (`KMeans` clustering) to analyze payload lengths and login frequencies, distinguishing opportunistic scanners from high-density automated botnets.
* **Geographic Threat Mapping**: Integrates IP geolocation queries with `Folium` to generate interactive visual maps of threat actors.
* **Structured Logging**: Stores real-time attack logs in structured JSON format for downstream SIEM integration or threat hunting pipelines.

## Tech Stack

* **Language**: Python 3
* **Libraries**: Paramiko, Scikit-learn, Folium, Pandas, Requests
* **Infrastructure**: Oracle Cloud Infrastructure (OCI) Ubuntu 22.04 VM

## Deployment & Usage

1. **Install Dependencies**:
   ```bash
   pip install paramiko scikit-learn folium pandas requests

   Generate Server Host Key:
   
    ssh-keygen -t rsa -b 2048 -f server.key -N ""

    Execute Honeypot & Profiler:

    python3 honeypot_profiler.py

        Select 1 to generate initial ML profiles and export attacker_map.html.

        Select 2 to start the live network listener on port 2222.

🗺️ Visualization

Generates an interactive HTML map rendering cluster distributions:

    Blue Markers: Low-density / Opportunistic authentication scans.

    Red Markers: High-density automated credential-stuffing campaigns.

