"""Project-wide constants.

This module also documents the non-negotiable operating constraints for the
framework. These are enforced in code (see `core.safety`), not just policy:

  * READ-ONLY ONLY: plugins may only invoke commands that gather information.
  * NO EXPLOITATION: the framework never attempts to trigger, weaponize, or
    validate a vulnerability by exploiting it.
  * NO DoS / NO STRESS: no fuzzing, brute forcing, load generation, or
    repeated hammering of services.
  * NO MUTATION: nothing in `collectors/` may write, delete, chmod, or
    otherwise change state on the host it is scanning.
  * HUMAN IN THE LOOP: everything the tool produces is a candidate for a
    human researcher to manually verify -- never an automatic verdict.
"""

from __future__ import annotations

from pathlib import Path

APP_NAME = "boss-auditor"
APP_VERSION = "0.1.0"

DEFAULT_CONFIG_PATH = Path("config/settings.yaml")
DEFAULT_PROFILE_DIR = Path("profiles")
DEFAULT_OUTPUT_DIR = Path("output")

BASELINE_PROFILE_NAME = "baseline_debian13.json"
TARGET_PROFILE_NAME = "target_bossos.json"

# Star-rating labels used by the (future) prioritization engine. Defined here
# so every layer of the codebase references the same vocabulary.
STAR_CRITICAL = "★★★★★ Critical Candidate"
STAR_HIGH = "★★★★ High Candidate"
STAR_MEDIUM = "★★★ Medium Candidate"
STAR_LOW = "★★ Low Candidate"
STAR_INFO = "★ Informational"

# Per-plugin timeout ceiling. Plugins must never block indefinitely on a
# host, and must never be given license to retry aggressively (that would
# start to look like load generation against a service).
DEFAULT_PLUGIN_TIMEOUT_SECONDS = 15
