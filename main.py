import requests
import hashlib
import sys


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
    for hash_local, count in hashes:
        if hash_local == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # Check if password exists in API response
    sha1pass = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1pass[:5], sha1pass[5:]
    response = request_api_data(first5_char)
    print(first5_char, tail)
    print(response)
    return get_password_leaks_count(response, tail)


def main(arguments):
    for password in arguments:
        count = pwned_api_check(password)
        if count:
            print(
                f"{password} was found {count} times... You should consider changing your password"
            )
        else:
            print(f"{password} was not found...")
    return "Done!"


main(sys.argv[1:])
