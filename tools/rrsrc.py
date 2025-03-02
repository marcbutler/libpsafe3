#!/usr/bin/env python3

# Recursively replace string in source code.

import logging
import os
import shutil
import sys
import tempfile


def is_c_source(filename: str) -> bool:
    _, ext = os.path.splitext(filename)
    return ext in [".c", ".C", ".h", ".H"]


def process(srcpath: str, matchstr: str, replacestr: str) -> None:
    tmppath = srcpath + ".tmp"
    updated = False
    logging.debug(f"Processing {srcpath}")
    with open(srcpath, "r") as file:
        with tempfile.NamedTemporaryFile(delete_on_close=False) as tmp:
            logging.debug(f"src={srcpath}  tmp={tmp.name}")
            for ln in file.readlines():
                modln = ln.replace(matchstr, replacestr)
                updated = updated or modln != ln
                if ln.find(matchstr) != -1:
                    logging.debug(f"{matchstr}  {replacestr}  {ln}  {modln}")
                    assert updated
                tmp.write(bytes(modln, "utf-8"))
            if updated:
                tmp.close()
                shutil.copyfile(tmp.name, tmppath)
    if updated:
        bakpath = srcpath + ".bak"
        shutil.copyfile(tmppath, bakpath)
        shutil.move(tmppath, srcpath)
        logging.info(f"{srcpath} modified")


def main():
    argcount = len(sys.argv) - 1
    assert argcount > 1 and argcount < 4

    matchstr, replacestr = sys.argv[1:3]
    rootdir = sys.argv[3] if argcount == 3 else os.getcwd()

    logging.info(f"match={matchstr}  replace={replacestr}  root={rootdir}")

    for rootdir, subdirs, files in os.walk(rootdir):
        src = [f for f in files if is_c_source(f)]
        subdirs[:] = [d for d in subdirs if d[0] != "." and d != "build"]
        logging.debug(f"{rootdir}  {subdirs}  {files}  {src}")
        for s in src:
            srcpath = os.path.join(rootdir, s)
            process(srcpath, matchstr, replacestr)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()
