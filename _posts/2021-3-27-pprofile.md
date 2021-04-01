---
layout: "post"
title: "Pprofile Line CTF 2021"
date: 2021-3-27
tags: [Linux Kernel,SMEP,SMAP,Kernel Heap]
---

I came across this eye-opening kernel challenge past week and although more than one good writeups exist, I would like to document my own clarity on the concept involved.

# TL;DR

+ Invoke the arbitrary write using `put_user_size`.
+ 




