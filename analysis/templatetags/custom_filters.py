# analysis/templatetags/custom_filters.py
from django import template
register = template.Library()

@register.filter(name='endswith')
def endswith(value, arg):
    """Returns True if the value ends with the argument string."""
    return str(value).lower().endswith(arg)


# @register.filter(name='add_class')
# def add_class(field, css):
#     return field.as_widget(attrs={"class": css})
