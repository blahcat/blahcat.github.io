import sys
import pathlib

fpath = pathlib.Path(sys.argv[1])
text = fpath.read_text(encoding="utf-8")

result = {}

#
# process file
#
while text:
    pattern_start = "\n> Processing: content/"
    pattern_start_len = len(pattern_start)

    start_idx = text.find(pattern_start)
    if start_idx < 0:
        break

    end_idx = text[start_idx + pattern_start_len :].find(pattern_start)
    final_block = end_idx < 0
    end_idx += start_idx + pattern_start_len

    # print(f"{final_block=}, {start_idx=}, {end_idx=}")

    if final_block:
        cur_block = text[start_idx:]
        text = None
    else:
        cur_block = text[start_idx:end_idx]
        text = text[end_idx:]

    assert cur_block.startswith(pattern_start)

    lines = [x for x in cur_block.splitlines() if x]
    if len(lines) < 2:
        continue

    article_path = lines[0].split()[2]

    words = [
        x
        for x in lines[1:]
        if x
        != "--------------------------------------------------------------------------------"
        and not x.startswith("<htmlcontent> content/")
        and not x.startswith("Misspelled words:")
        and not x.startswith("!!!Spelling check failed!!!")
    ]

    # print(f"{article_path=}, {start_idx=}, {end_idx=}, {words=}")
    result[article_path] = sorted(words)

#
# output as markdown table
#
print("| 📖 Page | ❌ Typo(s) |")
print("|---------|-------------|")

for page, words in result.items():
    print(f"|`{page}`| {', '.join(words)} |")
