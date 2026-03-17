---
layout: page
title: CVEs
icon: fas fa-shield-halved
order: 3
permalink: /cve/
---

<ul>
{% for post in site.categories.CVE %}
  <li>
    <a href="{{ post.url }}">{{ post.title }}</a>
    <span>({{ post.date | date: "%Y-%m-%d" }})</span>
  </li>
{% endfor %}
</ul>