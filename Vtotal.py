import requests

globvar = 0


def posting():

    global globvar

    url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    params = {'apikey': 'a645099a57655a8be21bde482b733ef0b7f72069005e22a582a9f823055c6572'}

    files= {'file': ('suspicious/drid.exe', open('suspicious/drid.exe', 'rb'))}

    post_response = requests.post(url, files=files, params=params)

    data = post_response.json()

    print('scan ID       :', data['scan_id'])
    print('sha1          :', data['sha1'])
    print('resource      :', data['resource'])
    print('sha256        :', data['sha256'])
    print('permalink     :', data['permalink'])
    print('md5           :', data['md5'])

    globvar = data['sha256']

#   print('globvar1', globvar)


def getting():

    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': 'a645099a57655a8be21bde482b733ef0b7f72069005e22a582a9f823055c6572', 'resource': globvar}

    response = requests.get(url, params=params)

    results = response.json()

    print('Total       :', results['total'])
    print('Positives   :', results['positives'])

    total_det = results['total']
    pos_det = results['positives']

    print("\nDetection ratio :", total_det, "/", pos_det)


def main():

    posting()
    getting()


if __name__ == "__main__" : main()










