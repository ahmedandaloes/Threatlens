# ThreatLens: 2.5-minute demo video script

**Setup before recording:** terminal and browser side by side; `streamlit run app.py` already running on `localhost:8501`; `examples/output/shifa_care_clinic_booking.html` open in a second tab; terminal font enlarged; no API key set, so the video shows offline mode (mention LLM mode in one line). Total ≈ 150 seconds at a calm pace (about 330 spoken words).

---

## English version

| # | Time | On screen | Voice-over |
|---|---|---|---|
| 1 | 0:00–0:15 | Title card: **ThreatLens — AI threat modeling for SMEs**. Then a slide: "3–5 consultant days · USD 1,500–4,500 · 1–3 weeks wait" | "A clinic in Cairo stores patient records. An online store in Alexandria takes Paymob payments. Both should have a threat model, but that means hiring a consultant for three to five days. So most SMEs skip it. I'm Ahmed Alaa Eldin, an application security consultant, and I built an agent that does that work." |
| 2 | 0:15–0:35 | Streamlit UI. Pick **🏥 Clinic booking (Egypt)**, expand "View input" to show the YAML for a few seconds | "This is ThreatLens. The input is what an SME already knows: the components, the data they hold, the integrations. Here it's a clinic with a Flutter app, a Laravel API, MySQL, lab-result storage, Paymob and WhatsApp reminders." |
| 3 | 0:35–0:55 | Click **Run threat model**. The status box lists each tool call: `parse_architecture`, `enumerate_components`, `stride_analyze_component`…, `reflect`, `render_report` | "When I click run, the agent plans the work and calls its tools one by one. It builds the asset inventory and trust boundaries, then runs STRIDE on every component and every data flow. Then it maps to OWASP and scores risk. Before it writes anything, it reflects on its own coverage and repairs any gaps." |
| 4 | 0:55–1:20 | Metric cards: Critical / High / Medium / Findings / dev-days. Open finding **TL-001 Forged webhook from Paymob**, then **TL-003 IDOR** | "Under a second later: forty-three findings, four of them critical. Number one is a forged Paymob callback. Without HMAC verification, anyone can mark a booking as paid. Number three is an IDOR: change one ID in the request and you read another patient's lab results. Every finding is mapped to OWASP Top 10, ASVS and CWE, with likelihood times impact." |
| 5 | 1:20–1:40 | **Remediation plan** tab: the top rows in "Now (0-2 weeks)", with the Owner and Effort columns | "Findings alone don't help a three-person team, so the agent turns them into a plan. Each fix has an owner and an effort in developer-days, ordered so the highest risk is closed first. MFA for staff and webhook signatures come first, and each takes one or two days." |
| 6 | 1:40–1:55 | **Data-flow diagram** tab: zoom on the red admin dashboard and the dashed (cleartext) arrows | "It also draws the data-flow diagram, with the trust zones and the hot spots in red. A founder can show this to an auditor or an investor." |
| 7 | 1:55–2:10 | Switch the input to **💊 Pharmacy delivery: free text**, run it, show the findings mentioning Moyasar and Unifonic | "No YAML? Paste a paragraph. This one describes a Riyadh pharmacy app, and the agent pulls out the architecture, including Moyasar payments and Unifonic SMS. It works with zero API keys. Add an Ollama Cloud or OpenAI key and an LLM drives the same tools and adds business-logic threats." |
| 8 | 2:10–2:30 | Terminal: `python -m threatlens examples/ecommerce_store.yaml --openapi …`, then `pytest -q` (green), then `docs/impact.md` headline | "It's the same from the command line, with an OpenAPI file for endpoint-level checks. The tests pass, and the benchmark is in the repo: a full threat model in milliseconds, 97 percent of my expert checklist covered, and 83 to 95 percent less expert time even with a human review. ThreatLens: a consultant-grade threat model for every SME, in minutes." |

---

## النسخة العربية (Arabic version)

| # | الوقت | على الشاشة | التعليق الصوتي |
|---|---|---|---|
| ١ | 0:00–0:15 | شاشة العنوان: **ThreatLens — نمذجة التهديدات بالذكاء الاصطناعي للشركات الصغيرة والمتوسطة**، ثم شريحة: "٣–٥ أيام استشاري · ١٥٠٠–٤٥٠٠ دولار · انتظار ١–٣ أسابيع" | "عيادة في القاهرة بتخزّن ملفات المرضى، ومتجر إلكتروني في إسكندرية بيستقبل مدفوعات عن طريق Paymob. الاتنين محتاجين نموذج تهديدات، لكن ده معناه استشاري لمدة من تلات لخمس أيام، فأغلب الشركات الصغيرة بتسيبه. أنا أحمد علاء الدين، استشاري أمن تطبيقات، وبنيت وكيل ذكي بيعمل الشغل ده." |
| ٢ | 0:15–0:35 | واجهة Streamlit، اختيار مثال **العيادة**، وفتح "View input" لعرض ملف YAML | "ده ThreatLens. المدخلات هي اللي الشركة عارفاها أصلًا: المكوّنات، والبيانات اللي فيها، والتكاملات. هنا عيادة عندها تطبيق Flutter، وواجهة برمجية Laravel، وقاعدة MySQL، وتخزين لنتائج التحاليل، وPaymob، وتذكير بالواتساب." |
| ٣ | 0:35–0:55 | الضغط على **Run threat model** وظهور استدعاءات الأدوات واحدة ورا التانية | "لما أضغط تشغيل، الوكيل بيخطط الشغل وبينادي أدواته خطوة بخطوة: بيعمل جرد للأصول وحدود الثقة، وبيطبّق STRIDE على كل مكوّن وكل تدفق بيانات، وبيربط النتايج بـ OWASP ويقيّم الخطورة. وقبل ما يكتب التقرير بيراجع تغطيته بنفسه ويصلّح أي نقص." |
| ٤ | 0:55–1:20 | بطاقات الخطورة، ثم فتح **TL-001 تزوير إشعار الدفع من Paymob**، ثم **TL-003 IDOR** | "في أقل من ثانية: تلاتة وأربعين ثغرة محتملة، منهم أربعة حرجة. الأولى تزوير إشعار الدفع من Paymob: من غير التحقق من توقيع HMAC أي حد يقدر يعلّم الحجز إنه مدفوع. والتالتة IDOR: تغيّر رقم واحد في الطلب فتشوف نتايج تحاليل مريض تاني. وكل ثغرة مربوطة بـ OWASP Top 10 وASVS وCWE، ومعاها الاحتمالية في الأثر." |
| ٥ | 1:20–1:40 | تبويب **خطة المعالجة**: صفوف "Now (0-2 weeks)" مع المسؤول والمجهود | "الثغرات لوحدها مش هتفيد فريق من تلات مطورين، فالوكيل بيحوّلها لخطة. كل إصلاح له مسؤول ومجهود بأيام المطورين، ومترتب بحيث يقفل أعلى خطر الأول. التحقق الثنائي للموظفين وتوقيع الإشعارات هما الأول، وكل واحد بياخد يوم أو اتنين." |
| ٦ | 1:40–1:55 | تبويب **مخطط تدفق البيانات**، والتركيز على لوحة الإدارة الحمرا والأسهم المتقطعة | "وكمان بيرسم مخطط تدفق البيانات، فيه مناطق الثقة والنقاط الساخنة بالأحمر، وصاحب الشركة يقدر يعرضه على مدقق أو مستثمر." |
| ٧ | 1:55–2:10 | تغيير المدخل لمثال **صيدلية التوصيل (نص حر)** وتشغيله | "مفيش YAML؟ الصق فقرة. دي بتوصف تطبيق صيدلية في الرياض، والوكيل استخرج المعمارية لوحده، ومعاها مدفوعات Moyasar ورسائل Unifonic. وكل ده من غير أي مفتاح API. ولو ضفت مفتاح Ollama Cloud أو OpenAI، نموذج لغوي هو اللي بيشغّل نفس الأدوات وبيضيف تهديدات خاصة بمنطق العمل." |
| ٨ | 2:10–2:30 | الطرفية: تشغيل `python -m threatlens` مع ملف OpenAPI، ثم `pytest -q` بالأخضر، ثم ملخص `docs/impact.md` | "ونفس الكلام من سطر الأوامر، ومع ملف OpenAPI علشان فحص على مستوى الـ endpoints. الاختبارات كلها ناجحة، والقياس موجود في المستودع: نموذج تهديدات كامل في أجزاء من الثانية، و٩٧٪ من قائمة الخبير متغطية، ووقت الخبير بيقل من ٨٣ لـ ٩٥٪ حتى مع المراجعة البشرية. ThreatLens: نموذج تهديدات بجودة الاستشاري لكل شركة صغيرة، في دقايق." |

> **Note on the Arabic:** the voice-over is in Egyptian colloquial Arabic, which suits an Egypt-based hackathon audience. For a Gulf or formal audience, re-voice it in Modern Standard Arabic; the screen directions stay the same.

---

## Recording checklist

- [ ] `pip install -r requirements.txt` done; `pytest -q` is green before recording
- [ ] No `.env` present (so offline mode is shown), or a separate take with `OLLAMA_API_KEY` set to show `mode: LLM via ollama-cloud · gpt-oss:120b`
- [ ] Browser zoom at 125%, dark terminal theme, notifications off
- [ ] Keep the numbers in the voice-over in step with `docs/impact.md` if the knowledge base changes
