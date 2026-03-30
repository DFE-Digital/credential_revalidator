# Credential Revalidator

Revalidates credentials found by Secret Scanners. Given a directory
will recursively scan subdirectorys for "trufflehog*.json", and
revalidate any secrets found. Optionally send results to Splunk.

# Usage

credential_revalidator validator [OPTIONS]

Options:

--send-to-splunk
    Send validation reports to Splunk

--splunk-hec-host <SPLUNK_HEC_HOST>
    Splunk HEC endpoint: e.g http-inputs-foobar.splunkcloud.com [env: SPLUNK_HEC_HOST=]

--splunk-hec-token <SPLUNK_HEC_TOKEN>
    Splunk HEC token [env: SPLUNK_HEC_TOKEN=]

--trufflhog-json-path <TRUFFLHOG_JSON_PATH>
    path to the root of the TruffleHog JSON files [default: "."]

--repo-details-path <REPO_DETAILS_PATH>
    Path to repo_details.csv

--detector-name <DETECTOR_NAME>
    filter only matching detector name

--repo-name <REPO_NAME>
    filter only matching repository name

--owner-name <OWNER_NAME>
    filter only matching owner name

--rerun-interval <RERUN_INTERVAL>
    run rerun validation continuiously after this delay in seconds

--no-validate
    Skip validation of secrets
