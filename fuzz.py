import argparse
import mechanicalsoup


class Fuzz:

    website = ''

    # Creating a browser object to access websites
    browser = mechanicalsoup.StatefulBrowser()
    # Creating a parser to enable this program to run on a command prompt.
    parser = argparse.ArgumentParser(prog="Fuzz tester",
                                     description='A fuzz tester that will test any given website for '
                                                 'vulnerabilities and then give a report on it.')
    # Creating the custom-auth argument to parser.
    parser.add_argument("--custom-auth=string",dest="custom",
                        help="Signal that the fuzzer should use hard-coded authentication for a specific application "
                             "(e.g. dvwa). Optional.")

    args = parser.parse_args()
    website = args.custom
    browser.open(website)
    browser.select_form()
    browser["username"] = "admin"
    browser["password"] = "password"
    response = browser.submit_selected()
    print(response.text)