# LOLesc1

`LOLesc1.ps1` is a PowerShell tool for Active Directory Certificate Services (AD CS) ESC1 workflow tasks.

It has two modes:

- **`enum`**: discover CAs and certificate templates, then show which templates look ESC1-usable for the current user.
- **`exploit`**: request and export a certificate (`.pfx`) for a target user through a selected ESC1-capable template.

---

## What the tool does

When you run the script, it:

1. Connects to LDAP and reads AD CS configuration.
2. Enumerates enterprise certification authorities (CAs).
3. Enumerates certificate templates.
4. Evaluates templates against ESC1-style conditions (subject control, approval settings, enrollment rights, authentication EKUs, and CA publication).
5. Either:
   - prints results (`enum` mode), or
   - builds a certificate request and exports a PFX (`exploit` mode).

---

## Quick start

```powershell
# Enumeration
.\LOLesc1.ps1 -Mode enum

# Exploitation flow
.\LOLesc1.ps1 -Mode exploit -TemplateName User -TargetUserSAN administrator@corp.local -OutputPath admin.pfx
```

---

## Full command syntax

```powershell
.\LOLesc1.ps1 -Mode <enum|exploit> [-TemplateName <string>] [-OutputPath <string>] [-TargetUserSAN <string>]
```

---

## Parameters (all flags explained)

### `-Mode` (required)

Selects which operation to run.

- `enum`: only enumerate and print AD CS / template findings.
- `exploit`: run the certificate request and export flow.

Example:

```powershell
.\LOLesc1.ps1 -Mode enum
```

---

### `-TemplateName` (optional in `enum`, required in `exploit`)

The certificate template name (or display name) to use in exploit mode.

- In `enum` mode, you can omit it.
- In `exploit` mode, the script will prompt until you provide a value if it is missing.

Example:

```powershell
.\LOLesc1.ps1 -Mode exploit -TemplateName User
```

---

### `-OutputPath` (optional)

Path where the exported `.pfx` file will be written.

- Default: `cert.pfx`
- Used in `exploit` mode.
- If parent folders do not exist, the script creates them.

Examples:

```powershell
.\LOLesc1.ps1 -Mode exploit -TemplateName User -TargetUserSAN administrator@corp.local -OutputPath cert.pfx
.\LOLesc1.ps1 -Mode exploit -TemplateName User -TargetUserSAN administrator@corp.local -OutputPath .\loot\admin.pfx
```

---

### `-TargetUserSAN` (optional in `enum`, required in `exploit`)

Target user identity used as the SAN/UPN in the request.

- In `enum` mode, not needed.
- In `exploit` mode, required.
- Accepts identities such as:
  - `administrator@corp.local`
  - `administrator`
  - other resolvable user identifiers

Example:

```powershell
.\LOLesc1.ps1 -Mode exploit -TemplateName User -TargetUserSAN administrator@corp.local
```

---

## Mode walkthroughs

## 1) Enumeration mode

Run:

```powershell
.\LOLesc1.ps1 -Mode enum
```

You will get:

- A CA table (`Name`, `DNSHostName`, template count).
- A full template table with key booleans.
- A focused “Potential ESC1 Templates” table.

Use this output to pick a template name for exploit mode.

---

## 2) Exploit mode

Run:

```powershell
.\LOLesc1.ps1 -Mode exploit -TemplateName <Template> -TargetUserSAN <target-upn> -OutputPath <file.pfx>
```

Flow:

1. Validates that the template is in the discovered exploitable set.
2. Selects a CA that publishes that template.
3. Resolves the target user to a SID.
4. Generates a temporary `.inf` and `.req`.
5. Uses `certreq.exe` to create, submit, and accept the certificate.
6. Prompts for a PFX password.
7. Exports the final PFX to your chosen output path.

---

## Interactive prompts

The script will prompt for missing required exploit values if you do not provide them as flags:

- `TemplateName`
- `TargetUserSAN`
- optionally `OutputPath`

During export, it also prompts for the PFX password.

---

## Common usage patterns

```powershell
# 1) Enumerate first
.\LOLesc1.ps1 -Mode enum

# 2) Exploit using a template found in output
.\LOLesc1.ps1 -Mode exploit -TemplateName User -TargetUserSAN administrator@corp.local -OutputPath administrator.pfx

# 3) Minimal exploit command (uses default OutputPath: cert.pfx)
.\LOLesc1.ps1 -Mode exploit -TemplateName User -TargetUserSAN administrator@corp.local
```

---

## Output summary

- **`enum` mode output**: CA inventory, template inventory, ESC1 candidate list.
- **`exploit` mode output**: status messages plus a PFX file at `-OutputPath`.

