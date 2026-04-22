# IndieHackers draft

## Title

```
After fixing two security bugs in my own security product, I'm finally launching it
```

## Body

```
I'm launching The Linux Security Suite today — a one-binary CIS hardening + audit + rollback tool for Linux servers, $149/$499/$1,499.

The story I want to share is what almost stopped me from launching: I had the product 80% built, the landing page approved, the wheel packaged. About to push the Buy button live. Then I asked an AI agent to do an unflinching code review.

It found two critical bugs in *my own security product*:

1. The HTML audit report interpolated the hostname, kernel string, and audit detail messages directly into HTML with no escaping. So if a customer's hostname was `<script>alert(1)</script>` (or anything more sinister), the report they emailed to their auditor was an XSS payload.

2. The rollback engine stored undo commands as f-string-interpolated shell strings and ran them with `shell=True`. Combined with the fact that some interpolated values come from system files an attacker might control, that's a root-level shell injection in the tool that's supposed to be hardening your system.

I spent the last two days rewriting the rollback engine. Undo storage is now `list[list[str]]` argv that runs with `shell=False`. The engine refuses to execute legacy string-form undos and warns the operator. There's a regression test that confirms a malicious `touch /tmp/sentinel` legacy undo is not executed. The XSS is fixed with `html.escape()` on every interpolated value.

Lessons that I think generalize:

- Get an unflinching review BEFORE you launch. The cost of finding bugs after a paying customer reports them is approximately infinite for a security product.
- Don't trust your own marketing claims. The landing page said "204 CIS controls" and the review caught that 6 of them were custom non-CIS checks I'd mislabeled. Fixed: renamed to LSS-001/002/003 namespace.
- Ship the v0.3 with honest beta framing. Don't pretend the per-control test suite exists when only the engine smoke tests do.

Pricing: $149 single host with 12mo updates, $499 up to 25 hosts with lifetime updates (the tier I think most small-ops buyers will land on), $1,499 enterprise unlimited. Source readable for evaluation — you can clone the repo and run the read-only audit before paying.

Landing page: https://linuxsecuritysuite.com
GitHub: https://github.com/<USERNAME>/lss

Happy to answer anything about the launch, the bugs, the pricing, or how I structured the rollback engine.
```

## Notes

- IH audience values transparency about mistakes more than polished launch posts. The "I almost shipped a product with XSS in the security product" angle is gold — use it.
- Expect questions about Gumroad vs Stripe Direct, pricing-tier naming, and "how did you validate demand."
- If you do a "Maker Story" follow-up post a week later with launch numbers, IH boosts it.
