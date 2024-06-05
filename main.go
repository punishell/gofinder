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
	"Heroku API KEY":                `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
	"possible_Creds":                `(?i)(password\s*[` + "`" + `=:"']+\s*[^\s]+|password is\s*[` + "`" + `=:"']*\s*[^\s]+|pwd\s*[` + "`" + `=:"']*\s*[^\s]+|passwd\s*[` + "`" + `=:"']+\s*[^\s]+)`,
}

const redColor = "\033[31m"
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
					fmt.Println(match)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
	}
}
