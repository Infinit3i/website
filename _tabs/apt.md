---
layout: page
title: APT
icon: fas fa-user-secret
order: 2
permalink: /apt/
---

<ul>
{% for post in site.categories.Apt %}
  <li>
    <a href="{{ post.url }}">{{ post.title }}</a>
    <span>({{ post.date | date: "%Y-%m-%d" }})</span>
  </li>
{% endfor %}
</ul>