import requests
import hashlib


def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f"Error fetching: {res.status_code}, check the API and try again"
        )
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    print(hashes)
    for h, count in hashes:
        print(h, count)


def pwned_api_check(password):
    # Check if password exists in API response
    sha1pass = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1pass[:5], sha1pass[5:]
    response = request_api_data(first5_char)
    print(first5_char, tail)
    print(response)
    return get_password_leaks_count(response, tail)


pwned_api_check("123")
