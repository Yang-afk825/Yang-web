# -*- coding: utf-8 -*-
"""Yang-Web 内嵌 CTF 脚本库 — 一键调用常用解题脚本."""



from .registry import SCRIPTS, CATEGORIES, list_scripts, search_scripts, get_script, get_script_path

from .runner import run_script, run_script_live, auto_solve

from .solver import solve_web

from .deps import (

    check_dep, check_all_deps, get_missing_deps,

    install_dep, install_all_missing, install_deps_for_script,

    get_scripts_by_dep, collect_all_deps,

)



__all__ = [

    "SCRIPTS",

    "CATEGORIES",

    "list_scripts",

    "search_scripts",

    "get_script",

    "get_script_path",

    "run_script",

    "run_script_live",

    "auto_solve",

    "solve_web",

    "check_dep",

    "check_all_deps",

    "get_missing_deps",

    "install_dep",

    "install_all_missing",

    "install_deps_for_script",

    "get_scripts_by_dep",

    "collect_all_deps",

]

