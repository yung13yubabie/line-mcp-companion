# Lieflat Less AI Tone — adapted rules

This directory contains a TypeScript adaptation of detection rules and rewrite
principles from **Lieflat Less AI Tone** (去AI味 v2) by shiujan:
https://github.com/larashero3-dotcom/lieflat-less-ai-tone

Original license: **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**
https://creativecommons.org/licenses/by-nc/4.0/

Changes made (as required by the license):
- Ported a subset of the regex rules in `scripts/detect.py` (levels A, B, H, F) from Python to TypeScript.
- Extended every pattern to match both Simplified and Traditional Chinese characters.
- Applied only to short chat replies; structural/document-level metrics (sentence-length CV,
  section geometry, isomorphic triples, synonym rotation) and the semantic layer are not ported.
- The rewrite step condenses the "改寫原則" (minimal edit, information preservation, no artificial
  rhythm, keep structure, conversational text is natural) into a model prompt, and adds an automatic
  information-preservation check that rejects rewrites that drop numbers, names, links or emoji.
- Rules the original research rejected ("X" level) are not used.

**This directory remains under CC BY-NC 4.0 and is NOT covered by the project's Apache-2.0 license.**
Non-commercial use only. For commercial use, obtain a license from the original author
(https://lieflat.work/skills/less-ai-tone/#pricing) or disable/remove this module.
The original author does not endorse this project.
