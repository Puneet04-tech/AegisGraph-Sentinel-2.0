### Description
While navigating the application, it is evident that several interactive components (such as icon-only buttons, modal close buttons, and custom dropdown triggers) lack proper WAI ARIA attributes. This creates a significant barrier for users relying on assistive technologies like screen readers.

### Proposed Solution
1. **Audit Buttons:** Scan the codebase for any `<button>`, `<a>`, or interactive `<div>` tags that contain only SVG icons and no text. Add descriptive `aria-label` attributes to these elements.
2. **Focus Management:** Ensure that modals trap focus correctly, and return focus to the triggering element upon closing.
3. **Semantic HTML:** Replace `<div>` elements used as buttons with actual `<button type="button">` tags to ensure native keyboard event handling (Space/Enter).

### Expected Outcome
The application will become fully accessible and compliant with WCAG 2.1 AA standards, providing an inclusive experience for disabled users.

**Suggested labels:** `gssoc`, `quality:clean`, `level:beginner`, `type:accessibility`
