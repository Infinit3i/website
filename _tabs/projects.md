---
layout: page
title: Projects
permalink: /projects/
icon: fas fa-code
order: 6
toc: true
---

{% assign projects = site.categories.project | sort: "date" | reverse %}
{% for post in projects %}
  {% assign cur_year = post.date | date: "%Y" %}
  {% if cur_year != last_year %}
    {% unless forloop.first %}</ul>{% endunless %}
    <time class="year lead d-block">{{ cur_year }}</time>
    <ul class="list-unstyled">
    {% assign last_year = cur_year %}
  {% endif %}

  <li><a href="{{ post.url | relative_url }}">{{ post.title }}</a></li>

  {% if forloop.last %}</ul>{% endif %}
{% endfor %}
