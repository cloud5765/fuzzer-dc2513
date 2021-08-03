def dvwa_relogin(browser):

    browser.open('http://127.0.0.1/dvwa/login.php')
    browser.select_form()
    browser['username'] = "admin"
    browser['password'] = "password"

    browser.submit_selected()

    browser.open("http://127.0.0.1/dvwa/security.php")
    browser.select_form()

    browser["security"] = "low"
    browser.submit_selected()

    return browser

def gruyere_relogin(browser, url):

    browser.open(url + 'login')
    browser.select_form()
    browser['uid'] = "badmojo"
    browser['pw'] = "humptydumpty"

    browser.submit_selected()


    return browser
