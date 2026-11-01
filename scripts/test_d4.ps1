# D4 Acceptance Runner: Executes all 3 required test questions with known correct answers.

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "             D4 -- AGENT ANSWERS TRUTH AUDIT (DOMAIN EVIDENCE)                  " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

Write-Host "`n>>> [TEST 1/3] Question 1: Customer at Day 45 Refund Request (POLICY-001)" -ForegroundColor Yellow
Write-Host "Expected: Memory POLICY-001 v1, Verified, Decision: REFUND DENIED" -ForegroundColor DarkGray
& "$PSScriptRoot\ask_agent.ps1" -Question "I bought an item 45 days ago. Can I get a refund?"

Write-Host "`n>>> [TEST 2/3] Question 2: Complaint Escalation Procedure (SOP-003)" -ForegroundColor Yellow
Write-Host "Expected: Memory SOP-003 v1, Verified, routed to Level 2 specialist within 24 hours" -ForegroundColor DarkGray
& "$PSScriptRoot\ask_agent.ps1" -Question "What is the procedure when a customer complaint requires escalation?"

Write-Host "`n>>> [TEST 3/3] Question 3: Support Availability & Contact FAQ (FAQ-001)" -ForegroundColor Yellow
Write-Host "Expected: Memory FAQ-001 v1, Verified, Mon-Fri 9am-6pm EST & 24/7 emergency" -ForegroundColor DarkGray
& "$PSScriptRoot\ask_agent.ps1" -Question "What are the customer support hours in the FAQ?"

Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "                         D4 ACCEPTANCE AUDIT COMPLETE                           " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

