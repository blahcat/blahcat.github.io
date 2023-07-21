"""
Populates the GITHUB_ENV with the information from the last published post.
The environment variables added are:

 - `BLOG_POST_TITLE` : the title of the blog post
 - `BLOG_POST_PUBLISHED_DATE` : the publication date
 - `BLOG_POST_URL` : the complete URL to the page
 - `BLOG_POST_SUMMARY` : the post summary
 - `BLOG_POST_SLUG_TITLE` :
 - `BLOG_POST_AUTHOR` :
"""
import requests
import bs4
import time
import os

ROOT: str = "https://blahcat.github.io"
URL: str = f"{ROOT}/feeds/all.atom.xml"

time.sleep(10)

h = requests.get(URL)
assert h.status_code == 200

soup = bs4.BeautifulSoup(h.text, "lxml")
node = soup.find("entry")
assert node is not None


def get(x: str):
    res = node.find(x)
    assert res
    return res


def strip_html(html: str):
    s = bs4.BeautifulSoup(html, features="html.parser")
    return s.get_text()


title = get("title").text
authors = [x.text for x in get("author").find_all("name")]
published = get("published").text
url = ROOT + get("link")["href"]
slug = get("link")["href"][18:-5]
summary = strip_html(get("summary").text)[:-3] + " [...]"

author_twitters = []
for author in authors:
    if author == "hugsy":
        author_twitters.append("@_hugsy_")
# TODO automate this

twitter_body = (
    f"""New blog post: '{title}' by {' and '.join(author_twitters)} - {url}"""
)
twitter_body = twitter_body[:280]


def env(x: str):
    os.system(f"echo {x} >> $GITHUB_ENV")


env(f"""BLOG_POST_TITLE="{title}" """)
env(f"""BLOG_POST_PUBLISHED_DATE="{published}" """)
env(f"""BLOG_POST_URL={url}""")
env(f"""BLOG_POST_SUMMARY="{summary}" """)
env(f"""BLOG_POST_SLUG_TITLE={slug}""")
env(f"""BLOG_POST_AUTHORS="{', '.join(authors)}" """)
env(f"""BLOG_POST_AUTHOR_TWITTER_HANDLES="{' and '.join(author_twitters)}" """)
env(f"""BLOG_POST_TWITTER_NOTIFICATION_BODY="{twitter_body}" """)
