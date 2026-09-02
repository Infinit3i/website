---
layout: page
title: APT
icon: fas fa-user-secret
order: 3
group: research
group_label: "Research"
group_icon: "fas fa-microscope"
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