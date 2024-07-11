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

from dataclasses import dataclass
from typing import Optional
import httpx
import bs4
import time
import os

ROOT: str = "https://blahcat.github.io"
ATOM_FEED_URL: str = f"{ROOT}/feeds/all.atom.xml"


@dataclass
class SocialMedia:
    twitter: Optional[str]
    mastodon: Optional[str]
    discord: Optional[str]
    github: Optional[str]


AUTHORS = {
    "hugsy": SocialMedia("@_hugsy_", "@hugsy@infosec.exchange", "@crazy.hugsy", "hugsy")
}

time.sleep(2)

h = httpx.get(ATOM_FEED_URL)
assert h.status_code == 200

soup = bs4.BeautifulSoup(h.text, "xml")
node = soup.find("entry")
assert node is not None


def get(x: str):
    res = node.find(x)
    assert res
    return res


def strip_html(html: str):
    s = bs4.BeautifulSoup(html, features="xml")
    return s.get_text()


def env(x: str):
    os.system(f"echo {x} >> $GITHUB_ENV")


title = get("title").text
authors = [x.text for x in get("author").find_all("name")]
published = get("published").text
url = str(get("link")["href"])
slug = str(get("link")["href"].rsplit("/")[-1])
summary = strip_html(get("summary").text)[:-3] + " [...]"

author_twitters = [
    AUTHORS[n].twitter for n in authors if n in AUTHORS and AUTHORS[n].twitter
]
twitter_body = (
    f"""New blog post: '{title}' by {' and '.join(author_twitters)} - {url}"""
)
twitter_body = twitter_body[:280]

env(f"""BLOG_POST_TITLE="{title}" """)
env(f"""BLOG_POST_PUBLISHED_DATE="{published}" """)
env(f"""BLOG_POST_URL={url}""")
env(f"""BLOG_POST_SUMMARY="{summary}" """)
env(f"""BLOG_POST_SLUG_TITLE={slug}""")
env(f"""BLOG_POST_AUTHORS="{', '.join(authors)}" """)
env(f"""BLOG_POST_AUTHOR_TWITTER_HANDLES="{' and '.join(author_twitters)}" """)
env(f"""BLOG_POST_TWITTER_NOTIFICATION_BODY="{twitter_body}" """)
