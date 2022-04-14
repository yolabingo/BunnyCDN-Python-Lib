from re import I


import sys

from bs4 import BeautifulSoup

def get_classes(element):
    try:
        return element['class']
    except KeyError:
        return []


def get_param_divs(soup):
    """
    get div containing all param data
    """
    for div in soup.find_all('div'):
        div_classes = get_classes(div)
        for c in div_classes:
            if c.startswith('Param-left'):
                yield div


def parse_param_div(div):
    """
    parse individual param info from div
    """
    param_name = param_type = param_desc = 'UNSET'
    for label in div.find_all('label'):
        param_name = (label.string)
    for child in div.find_all('div'):
        for c in get_classes(child):
            if c.startswith('Param-type'):
                param_type = child.string
    for desc in div.find_all('p'):
        param_desc = desc.string
    return (param_name, param_type, param_desc)


# with open("pullzonepublic_updatepullzone-result-20220414003331") as fp:
with open("pullzonepublic_updatepullzone") as fp:
    soup = BeautifulSoup(fp, 'html.parser')

for d in get_param_divs(soup):
    print(parse_param_div(d))