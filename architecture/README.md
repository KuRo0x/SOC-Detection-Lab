# Architecture

This folder contains the lab architecture diagram.

## Diagram

![Architecture Diagram](https://raw.githubusercontent.com/KuRo0x/vSOC-Lab/main/architecture/architecture-diagram.png)

> **Note:** Replace with local `architecture-diagram.png` once images are moved to this repo.

## What It Shows

- Isolated virtual network (VMnet3)
- pfSense as the single enforced gateway
- Windows 10 endpoint with Sysmon + Winlogbeat
- Ubuntu SIEM running ELK Stack + Suricata
- Log ingestion paths from each source to Elasticsearch
