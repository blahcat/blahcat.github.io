AUTHOR = 'hugsy'
SITENAME = 'BlahCats'
SITEURL = ''
SITESUBTITLE = 'Tales of a binary encoded life...'
PATH = 'content'

TIMEZONE              = 'America/Vancouver'
DEFAULT_LANG          = 'en'
DEFAULT_DATE          =  'fs'
DEFAULT_DATE_FORMAT   = '%d %b %Y'

# Feed generation is usually not desired when developing
FEED_ALL_ATOM            = None
CATEGORY_FEED_ATOM       = None
TRANSLATION_FEED_ATOM    = None
AUTHOR_FEED_ATOM         = None
AUTHOR_FEED_RSS          = None

# Blogroll
LINKS = (
  ('TheGoonies CTF', 'https://thegooniesctf.github.io/'),
  ('Bernardo', 'https://w00tsec.blogspot.com/'),
  ('Danilo', 'https://bugnotfound.com'),
  ('grazfather', 'http://grazfather.github.io/'),
  ('Diary of a Reverse Engineer', 'https://doar-e.github.io/'),
  ('Connor McGarr', 'https://connormcgarr.github.io'),
  ('tiraniddo.dev', 'https://tiraniddo.dev'),
  ('zodiacon\'s blog', 'https://scorpiosoftware.net/')
)

# Social widget
SOCIAL = (
    ('Twitter', 'https://twitter.com/ctf_blahcat'),
    ('Github', 'https://github.com/blahcat'),
)

DEFAULT_PAGINATION = 10
PAGINATION_PATTERNS = (
    (1, '{base_name}/', '{base_name}/index.html'),
    (2, '{base_name}/page/{number}/', '{base_name}/page/{number}/index.html'),
)

DISPLAY_CATEGORIES_ON_MENU = False
DISPLAY_PAGES_ON_MENU = False

MENUITEMS = (
    ('About', '/pages/about.html'),
    ('Browse By Category', '/categories/'),
    ('Browse By Tag', '/tags/'),
    ('Qemu VMs', '/pages/qemu-vm-repo'),
    ('Exploitation Tutorials', '/pages/exploitation-series'),
)

# Uncomment following line if you want document-relative URLs when developing
#RELATIVE_URLS = True

PLUGINS = [
  'sitemap',
  'neighbors',
]

STATIC_PATHS = [
    'assets',
    'assets/images',
]

PYGMENTS_RST_OPTIONS = {'classprefix': 'pgcss', 'linenos': 'inline'}

EXTRA_PATH_METADATA = {
    'assets/images/favicon.ico': {'path': 'favicon.ico'},
}

# Sitemap plugin settings
SITEMAP = {
    'format': 'xml',
    'priorities': {
        'articles': 0.5,
        'indexes': 0.5,
        'pages': 0.5
    },
    'changefreqs': {
        'articles': 'monthly',
        'indexes': 'daily',
        'pages': 'monthly'
    }
}

# Post and Pages path
ARTICLE_URL              = 'posts/{date:%Y}/{date:%m}/{date:%d}/{slug}.html'
ARTICLE_SAVE_AS          = 'posts/{date:%Y}/{date:%m}/{date:%d}/{slug}.html'
PAGE_URL                 = 'pages/{slug}.html'
PAGE_SAVE_AS             = 'pages/{slug}.html'
YEAR_ARCHIVE_SAVE_AS     = 'archives/{date:%Y}/index.html'
MONTH_ARCHIVE_SAVE_AS    = 'archives/{date:%Y}/{date:%m}/index.html'

# Tags and Category path
CATEGORY_URL          = 'category/{slug}'
CATEGORY_SAVE_AS      = 'category/{slug}/index.html'
CATEGORIES_SAVE_AS    = 'categories/index.html'
TAG_URL               = 'tag/{slug}'
TAG_SAVE_AS           = 'tag/{slug}/index.html'
TAGS_SAVE_AS          = 'tags/index.html'
DRAFT_URL             = 'drafts/{slug}.html'

# Author
AUTHOR_URL           = 'author/{slug}'
AUTHOR_SAVE_AS       = 'author/{slug}/index.html'
AUTHORS_SAVE_AS      = 'authors.html'

CSS_OVERRIDE = [
    'https://fonts.googleapis.com/css?family=Roboto',
    'assets/css/overrides.css',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css',
]

JS_OVERRIDE = [
    'https://cdnjs.cloudflare.com/ajax/libs/mermaid/9.1.1/mermaid.min.js',
]

# Theme settings
THEME = 'attila'
HEADER_COVER = 'assets/images/blog-cover.png'
AUTHORS_BIO = {
  "hugsy": {
    "name": "hugsy",
    "cover": "https://i.imgur.com/XrHeJlW.png",
    "image": "assets/images/authors/hugsy.png",
    "website": "/author/hugsy",
    "twitter": "_hugsy_",
    "github": "hugsy",
    "bio": "BWAAAAHHHH"
  }
}

COLOR_SCHEME_CSS = 'github.css'

HEADER_COVERS_BY_TAG = {
    # 'cupcake': 'assets/images/rainbow_cupcake_cover.png',
    # 'general':'https://casper.ghost.org/v1.0.0/images/writing.jpg'
}
