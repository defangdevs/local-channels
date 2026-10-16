"""Run local-slack's real main() with Slack's Web API redirected to the mock."""
import os, sys, urllib.request
sys.path.insert(0, os.path.join(os.environ['REPO'], 'local-slack'))
import slack  # noqa: E402

MOCK = os.environ['MOCK_SLACK']
_orig = urllib.request.urlopen


def urlopen(req, *a, **k):
    url = req.full_url if isinstance(req, urllib.request.Request) else req
    if url.startswith('https://slack.com/'):
        new = MOCK + url[len('https://slack.com'):]
        if isinstance(req, urllib.request.Request):
            req.full_url = new
        else:
            req = new
    return _orig(req, *a, **k)


urllib.request.urlopen = urlopen
sys.exit(slack.main(sys.argv[1:]))

