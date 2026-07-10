import subprocess
import time

comments = {
    3386: """Hi! I looked into this memory leak issue regarding the WebSocket connections in the live chat component.

What I found & My Plan:
Memory leaks in WebSockets often occur due to unclosed connections or lingering event listeners when components unmount. I plan to review the chat component's lifecycle methods to ensure connections are properly closed and listeners are removed when the user navigates away. I will also check for any detached DOM elements keeping references.

Technologies: React/Next.js, WebSockets, JavaScript Memory Management.

Can I work on this under GSSoC'26? I would love to be assigned so I can start working on a PR!""",

    3385: """Hi! I looked into this performance issue regarding responsive image loading and WebP conversion.

What I found & My Plan:
To optimize image delivery, we need to serve appropriately sized images based on the user's device and use next-gen formats like WebP. I plan to update our image components to support srcset and sizes. I'll also configure our build pipeline or image loader to automatically convert static assets to WebP.

Technologies: HTML/CSS, React, WebP optimization.

Can I work on this under GSSoC'26? I would love to be assigned so I can start working on a PR!""",

    3384: """Hi! I looked into this PWA feature regarding push notification support for background sync completion.

What I found & My Plan:
To notify users when their background tasks finish, we need to integrate the Push API and Service Workers. I plan to update our existing service worker to listen for the sync event completion and trigger a push notification. I'll also add the necessary UI prompts to request notification permissions from the user.

Technologies: Service Workers, Push API, JavaScript, PWA.

Can I work on this under GSSoC'26? I would love to be assigned so I can start working on a PR!""",

    3383: """Hi! I looked into this accessibility issue regarding screen reader compatibility for custom dropdown components.

What I found & My Plan:
Custom dropdowns often lack native semantics, making them invisible or confusing for screen readers. I plan to add the appropriate ARIA roles (like `listbox`, `option`) and `aria-expanded`/`aria-activedescendant` attributes to the dropdown markup. I will also ensure proper keyboard navigation (Up/Down arrows, Enter, Escape) is supported.

Technologies: React, HTML/CSS, Web Accessibility (a11y), ARIA.

Can I work on this under GSSoC'26? I would love to be assigned so I can start working on a PR!""",

    3382: """Hi! I looked into this infrastructure feature regarding health check endpoints for our microservices.

What I found & My Plan:
To effectively monitor our services, orchestrators and load balancers need a reliable health check. I plan to implement standard `/healthz` endpoints in each service that check database connectivity and essential dependencies. These endpoints will return a 200 OK when healthy and appropriate error codes when degraded.

Technologies: Node.js/Express, Docker/Kubernetes concepts, API Design.

Can I work on this under GSSoC'26? I would love to be assigned so I can start working on a PR!""",

    3381: """Hi! I looked into this performance issue regarding slow Prisma queries on the admin dashboard analytics page.

What I found & My Plan:
The slow queries are likely due to N+1 query problems or missing database indexes. I plan to use Prisma's `include` and `select` cautiously, perhaps switching to raw SQL or aggregations for complex analytics. I will also review the schema to ensure appropriate indexes are in place for the queried fields.

Technologies: Node.js, Prisma ORM, PostgreSQL/MySQL, Database Optimization.

Can I work on this under GSSoC'26? I would love to be assigned so I can start working on a PR!""",

    3380: """Hi! I looked into this authentication bug regarding the race condition in the token refresh flow during concurrent API requests.

What I found & My Plan:
When multiple requests fail simultaneously due to an expired token, they all might try to trigger a refresh, leading to race conditions. I plan to implement a token refresh lock or a promise queue in our API client (e.g., Axios interceptor) so that only the first request triggers the refresh, and subsequent requests wait for it to complete.

Technologies: JavaScript/TypeScript, Axios/Fetch, Authentication flows.

Can I work on this under GSSoC'26? I would love to be assigned so I can start working on a PR!""",

    3379: """Hi! I looked into this API security feature to add rate limiting and abuse prevention middleware.

What I found & My Plan:
To protect our API from abuse and DDoS attacks, we need rate limiting. I plan to integrate `express-rate-limit` (or similar depending on the framework) to restrict the number of requests per IP within a time window. I'll also explore setting up Redis for distributed rate limiting if we have multiple instances.

Technologies: Node.js, Express/Next.js, Redis, API Security.

Can I work on this under GSSoC'26? I would love to be assigned so I can start working on a PR!""",

    3378: """Hi! I looked into this accessibility issue to enhance keyboard navigation and focus management in modal dialogs.

What I found & My Plan:
When a modal opens, focus should be trapped within it, and when it closes, focus should return to the triggering element. I plan to implement a focus trap mechanism and add proper ARIA roles (`dialog`, `aria-modal="true"`) to the modal container. I will ensure Esc key support for closing the dialog.

Technologies: React, JavaScript, Web Accessibility (a11y), DOM Management.

Can I work on this under GSSoC'26? I would love to be assigned so I can start working on a PR!""",

    3377: """Hi! I looked into this frontend performance issue to implement code splitting and lazy loading for heavy components.

What I found & My Plan:
Large bundle sizes slow down initial page loads. I plan to identify heavy, non-critical components (like charts or large tables) and use `React.lazy` and `Suspense` (or dynamic imports in Next.js) to load them asynchronously only when they are needed. This will significantly reduce the initial JavaScript payload.

Technologies: React, Webpack/Vite, Frontend Optimization.

Can I work on this under GSSoC'26? I would love to be assigned so I can start working on a PR!""",

    3376: """Hi! I looked into this PWA feature to implement an offline fallback page for un-cached routes.

What I found & My Plan:
When users are offline and navigate to a route that hasn't been cached, they shouldn't see a browser error. I plan to update the service worker to catch failed network requests and serve a pre-cached offline HTML page. I will design a user-friendly offline fallback indicating their connection status.

Technologies: Service Workers, HTML/CSS, PWA, Cache API.

Can I work on this under GSSoC'26? I would love to be assigned so I can start working on a PR!"""
}

for issue_id, comment_body in comments.items():
    print(f"Commenting on issue #{issue_id}...")
    try:
        subprocess.run(["gh", "issue", "comment", str(issue_id), "--repo", "Ayushh-Sharmaa/NexaSphere", "--body", comment_body], check=True)
        print(f"Successfully commented on #{issue_id}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to comment on #{issue_id}: {e}")
    time.sleep(2)  # Delay to prevent rate limiting
