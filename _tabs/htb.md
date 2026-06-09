---
layout: page
title: HTB
icon: fas fa-cube
order: 1
permalink: /htb/
---

<div class="htb-page-header">
  <img src="/assets/Images/htb-logo.svg" alt="HackTheBox" class="htb-logo">
</div>

{% assign htb_posts = site.categories.HackTheBox %}

{% assign difficulties = "Easy,Medium,Hard,Insane" | split: "," %}
{% for difficulty in difficulties %}
  {% assign diff_lower = difficulty | downcase %}
  {% assign diff_posts = "" | split: "" %}
  {% for post in htb_posts %}
    {% if post.tags contains diff_lower %}
      {% assign diff_posts = diff_posts | push: post %}
    {% endif %}
  {% endfor %}
  {% if diff_posts.size > 0 %}
  <details class="htb-difficulty htb-{{ diff_lower }}">
    <summary>{{ difficulty }} <span style="opacity:0.6;font-weight:400;">({{ diff_posts.size }})</span></summary>
    <ul>
      {% for post in diff_posts %}
        <li class="htb-post-item">
          {% if post.image.path %}
            <img src="{{ post.image.path }}" alt="{{ post.title }}" class="htb-post-thumb">
          {% else %}
            <span class="htb-post-thumb htb-post-thumb-placeholder"></span>
          {% endif %}
          <a href="{{ post.url }}">{{ post.title }}</a>
          <span class="post-date">({{ post.date | date: "%Y-%m-%d" }})</span>
        </li>
      {% endfor %}
    </ul>
  </details>
  {% endif %}
{% endfor %}
