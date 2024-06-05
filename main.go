package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
)

var regexPatterns = map[string]string{
    "google_api":                    `AIza[0-9A-Za-z-_]{35}`,
    "firebase":                      `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`,
    "google_captcha":                `6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$`,
    "google_oauth":                  `ya29\.[0-9A-Za-z\-_]+`,
    "amazon_aws_access_key_id":      `A[SK]IA[0-9A-Z]{16}`,
    "amazon_mws_auth_toke":          `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
    "amazon_aws_url":                `s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com`,
    "amazon_aws_url2":               `[a-zA-Z0-9-._]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-._]+|s3-[a-zA-Z0-9-._/]+|s3.amazonaws.com/[a-zA-Z0-9-._]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-._]+`,
    "facebook_access_token":         `EAACEdEose0cBA[0-9A-Za-z]+`,
    "authorization_basic":           `basic [a-zA-Z0-9=:_\+\/-]{5,100}`,
    "authorization_bearer":          `bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}`,
    "authorization_api":             `api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}`,
    "mailgun_api_key":               `key-[0-9a-zA-Z]{32}`,
    "twilio_api_key":                `SK[0-9a-fA-F]{32}`,
    "twilio_account_sid":            `AC[a-zA-Z0-9_\-]{32}`,
    "twilio_app_sid":                `AP[a-zA-Z0-9_\-]{32}`,
    "paypal_braintree_access_token": `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
    "square_oauth_secret":           `sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`,
    "square_access_token":           `sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}`,
    "stripe_standard_api":           `sk_live_[0-9a-zA-Z]{24}`,
    "stripe_restricted_api":         `rk_live_[0-9a-zA-Z]{24}`,
    "github_access_token":           `[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*`,
    "rsa_private_key":               `-----BEGIN RSA PRIVATE KEY-----`,
    "ssh_dsa_private_key":           `-----BEGIN DSA PRIVATE KEY-----`,
    "ssh_dc_private_key":            `-----BEGIN EC PRIVATE KEY-----`,
    "pgp_private_block":             `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
    "json_web_token":                `ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`,
    "slack_token":                   `"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"`,
    "SSH_privKey":                   `([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`,
    "heroku_api_key":                `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
    "possible_creds":                `(?i)(password\s*[` + "`" + `=:"']+\s*[^\s]+|password is\s*[` + "`" + `=:"']*\s*[^\s]+|pwd\s*[` + "`" + `=:"']*\s*[^\s]+|passwd\s*[` + "`" + `=:"']+\s*[^\s]+)`,
    "abtasty_api_key":               `Authorization: x-api-key `,
    "algolia_api_key":               `x-algolia-api-key: `,
    "amplitude_api_keys":            `Basic `,
    "asana_access_token":            `Bearer `,
    "aws_secret_access_key":         `(?i)aws_secret_access_key`,
    "azure_application_insights":    `x-api-key: `,
    "bazaarvoice_passkey":           `conversationspasskey=`,
    "bitly_access_token":            `access_token=`,
    "branch_io_key_secret":          `branch_secret=`,
    "browserstack_access_key":       `ACCESS_KEY`,
    "buttercms_api_key":             `auth_token=`,
    "calendly_api_key":              `X-TOKEN: `,
    "contentful_access_token":       `access_token=`,
    "circleci_access_token":         `circle-token=`,
    "cypress_record_key":            `recordKey`,
    "datadog_api_key":               `api_key=`,
    "deviant_art_access_token":      `access_token=`,
    "deviant_art_secret":            `client_secret=`,
    "facebook_appsecret":            `client_secret=`,
    "firebase_custom_token":         `token=`,
    "firebase_api_key":              `key=`,
    "github_client_id_secret":       `client_secret=`,
    "github_private_ssh_key":        `-----BEGIN RSA PRIVATE KEY-----`,
    "gitlab_personal_access_token":  `private_token=`,
    "gitlab_runner_registration_token": `registration-token `,
    "google_cloud_service_account":  `"private_key": "-----BEGIN PRIVATE KEY-----`,
    "google_maps_api_key":           `key=`,
    "google_recaptcha_key":          `secret=`,
    "grafana_access_token":          `Authorization: Bearer `,
    "help_scout_oauth":              `client_secret=`,
    "hubspot_api_key":               `hapikey=`,
    "instagram_access_token":        `access_token=`,
    "ipstack_api_key":               `access_key=`,
    "iterable_api_key":              `Api_Key: `,
    "jumpcloud_api_key":             `x-api-key: `,
    "keen_io_api_key":               `api_key=`,
    "linkedin_oauth":                `client_secret=`,
    "lokalise_api_key":              `x-api-token: `,
    "loqate_api_key":                `Key=`,
    "mapbox_api_key":                `access_token=`,
    "microsoft_azure_tenant":        `client_secret=`,
    "microsoft_sas":                 `sig=`,
    "new_relic_personal_api_key":    `API-Key: `,
    "new_relic_rest_api":            `X-Api-Key:`,
    "npm_token":                     `_authToken=`,
    "opsgenie_api_key":              `Authorization: GenieKey `,
    "pagerduty_api_token":           `Authorization: Token token=`,
    "pendo_integration_key":         `x-pendo-integration-key: `,
    "pivotaltracker_api_token":      `X-TrackerToken: `,
    "salesforce_api_key":            `Authorization: Bearer `,
    "sendgrid_api_token":            `Authorization: Bearer `,
    "shodan_api_key":                `key=`,
    "slack_api_token":               `token=xoxp-`,
    "slack_webhook":                 `https://hooks.slack.com/services/`,
    "spotify_access_token":          `Authorization: Bearer `,
    "square_api_key_secret":         `Authorization: Client `,
    "stripe_live_token":             `sk_live_`,
    "travis_ci_api_token":           `Authorization: token `,
    "twitter_bearer_token":          `authorization: Bearer `,
    "visual_studio_app_center_api_token": `X-Api-Token: `,
    "wpengine_api_key":              `wpe_apikey=`,
    "youtube_api_key":               `key=`,
}

const redColor = "\033[31m"
const greenColor = "\033[32m"
const resetColor = "\033[0m"

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := scanner.Text()
		resp, err := http.Get(url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching URL: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading response body: %v\n", err)
			continue
		}

		content := string(body)
		for name, pattern := range regexPatterns {
			re := regexp.MustCompile(pattern)
			matches := re.FindAllString(content, -1)
			if len(matches) > 0 {
				fmt.Printf("%sMatches for %s:%s\n", redColor, name, resetColor)
				for _, match := range matches {
					fmt.Printf("%s%s%s\n", greenColor, url, resetColor)
					fmt.Println(match)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
	}
}
