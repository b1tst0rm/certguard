import json
import logging  # for CloudWatch logs
from botocore.vendored import requests
from datetime import datetime

TEAMS_ENDPOINT = "SET THIS (ie., https://outlook.office.com/webhook/...)"
SECURITY_TOKEN = "SET THIS"
TEAMS_CARD = """
{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    "themeColor": "FF0000",
    "title": "Alert: Potentially Malicious Domain Discovered!",
    "text": "Facebook Certificate Transparency Monitoring System has detected a new SSL certificate issued for what looks to be an illegitimate domain similar to ",
    "sections": [
        {
            "startGroup": true,
            "title": "DOMAIN: **mal.blah.d.com**",
            "facts": [
                {
                    "name": "Date submitted:",
                    "value": "06/27/2017, 2:44 PM"
                }
            ]
        },
        {
            "startGroup": true,
            "potentialAction": [
                {
                    "@type": "OpenUri",
                    "name": "Learn more about Facebook Certificate Transparency",
                    "targets": [
                        {
                            "os": "default",
                            "uri": "https://developers.facebook.com/docs/certificate-transparency/"
                        }
                    ]
                }
            ]
        }
    ]
}
"""

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info('got event {}'.format(event))
    retval = json.dumps(event)

    # Facebook certificate transparency monitor initially performs
    # a GET request to verify the API is up and functioning properly
    if (event['httpMethod'] == 'GET'):
        if (event['queryStringParameters']['hub.verify_token'] ==
                SECURITY_TOKEN):
            logger.info('API GET call successful')
            return {
                'statusCode': 200,
                'body': event['queryStringParameters']['hub.challenge']
            }
        else:
            logger.error('API GET call failed')
            return {
                'statusCode': 400,
                'body': 'Something went wrong'
            }
    elif (event['httpMethod'] == 'POST'):
        # Fetch the JSON body from Facebook
        body = json.loads(event['body'])
        
        try:
            # If more than one alert in the payload
            changes_value = body['entry'][0]['changes'][0]['value']
            domains = changes_value['phishing_domains']
            original_domain = changes_value['phished_domain']
            
            for domain in domains:
                time = datetime.utcfromtimestamp(
                    int(body['entry'][0]['time'])
                ).strftime('%Y-%m-%d %H:%M:%S') + " UTC"
                relay_alert(original_domain, domain, time)

        except KeyError:
            # If just one alert in the body
            mal_domain = body['value']['phishing_domains'][0]
            original_domain = body['value']['phished_domain']
            time = datetime.utcfromtimestamp(
                int(body['time'])
            ).strftime('%Y-%m-%d %H:%M:%S') + " UTC"
            relay_alert(original_domain, mal_domain, time)

        return {
            'statusCode': 200,
            'body': 'success'
        }
    else:
        logger.error('Invalid HTTP method hit')
        return {
            'statusCode': 400,
            'body': 'Invalid HTTP Method'
        }

def relay_alert(orig_domain, mal_domain, time):
    """
    Given the original domain, malicious/phishing domain, and time of
    occurrence, sends an alert to Teams endpoint using a formatted Card.
    """
    card_to_send = json.loads(TEAMS_CARD)
    card_to_send['text'] += '**' + orig_domain + '**'
    card_to_send['sections'][0]['title'] = '**' + mal_domain + '**'
    card_to_send['sections'][0]['facts'][0]['value'] = time
    json_teams_str = json.dumps(card_to_send)
    r = requests.post(TEAMS_ENDPOINT, data=json_teams_str)
