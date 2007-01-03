#!/usr/bin/env python

table = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

def convert(current):
  # Possibilities with each character
  # 1: 36 = 36
  # 2: 36*36 = 1296
  # 3: 36*36*36 = 46656

  res = ""
  length = len(table) - 1

  if current / length > 0:
    res += convert(current / length)

  res += table[current % length]

  return res
