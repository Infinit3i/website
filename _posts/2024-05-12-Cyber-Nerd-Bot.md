---
title: "Cyber Nerd Discord Bot"
date: 2024-05-12 10:00:00 -0500
categories: [Project, GitHub]
tags: [cybersecurity, discord bot, javascript, automation, rss, threat intel, ioc, mitre attack, detection engineering, infosec]
image:
  path: https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSVjI44K0gKx2rTnCiFSaVz8xvn9r7uJYdg-w&s
---

# Cyber Nerd Discord Bot

The **Cyber Nerd Discord Bot** is an interactive cybersecurity learning bot designed to continuously challenge and educate users through daily questions, live updates, and automated intelligence drops.

It is built entirely in **JavaScript** and served as a major learning milestone for me. Through this project, I learned how to:
- Consume and normalize **RSS feeds**
- Pull data from multiple **news outlets**
- Schedule and **continuously push updates**
- Handle **edge cases**, failures, and malformed data gracefully

The bot creates a steady flow of cybersecurity knowledge while reinforcing consistency, automation, and reliability—core skills for detection engineering and security operations.

**[Join my server](https://discord.gg/rzSTrk39yE)** 

## Features
- 📰 **Grabs News Articles:** Automatically fetches and shares trending news.
- ❓ **Quiz Chat Answers:** Interactive daily cybersecurity questions.
- 🎉 **Victory Celebrations:** Milestones every 5 correct answers.
- ⭐ **Special Questions:** Unique questions multiple times per day.
- 🎊 **Holiday Celebrations:** Context-aware holiday logic.
- ⏰ **IOC Updates:** New Indicator of Compromise every 4 hours.
- 🛠️ **MITRE ATT&CK Updates:** Framework updates every 6 hours.
- 🗓️ **Event Code Updates:** New event code every 8 hours.

## Slash Commands

```
/question      - asks a question
/leaderboard   - shows top performers
/score         - displays your score
/blank         - masks the answer (e.g., Phishing → xxxxxxxx)
/hint          - provides a hint
/skip          - skips the current question
```