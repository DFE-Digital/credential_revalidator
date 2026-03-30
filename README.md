# Credential Revalidator

Revalidates credentials found by Secret Scanners. Given a directory
will recursively scan subdirectorys for "trufflehog*.json", and
revalidate any secrets found. Optionally send results to Splunk.

# Usage

access_monitor validator [OPTIONS] --repo-details-path <REPO_DETAILS_PATH>

Options:
      --send-to-splunk
          Send validation reports to Splunk
      --splunk-hec-host <SPLUNK_HEC_HOST>
          http-inputs-foobar.splunkcloud.com
      --splunk-hec-token <SPLUNK_HEC_TOKEN>

      --trufflhog-json-path <TRUFFLHOG_JSON_PATH>
          The path to the directory containing all Trufflehog logs [default: "."]
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
