import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import {
  ArrowLeft,
  BarChart3,
  Bell,
  FileText,
  Github,
  Menu,
  Shield,
  Target,
  Zap,
  AlertCircle,
  X,
} from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { PageShell } from "@/components/app/ui";
import { DemoAssistant } from "@/components/demo/demo-assistant";
import {
  DemoActivity,
  DemoDashboard,
  DemoReports,
  DemoRepositories,
  DemoScans,
  DemoVulnerabilities,
} from "@/components/demo/demo-sections";

/**
 * Public, unauthenticated product tour at /demo.
 *
 * Deliberately NOT nested under _authenticated: that layout's beforeLoad
 * redirects signed-out visitors to /auth, which is exactly what made the old
 * "View Live Demo" button a dead end.
 *
 * Everything rendered here reads from lib/demo-data.ts. No Supabase client, no
 * server function and no fetch is imported anywhere in this subtree, so no
 * interaction can touch real data.
 */
export const Route = createFileRoute("/demo")({
  head: () => ({
    meta: [
      { title: "Live Demo — PentestAI" },
      {
        name: "description",
        content:
          "Explore PentestAI with a simulated repository and sample security findings. No sign-in required.",
      },
    ],
  }),
  component: DemoPage,
});

type SectionId = "dashboard" | "repositories" | "scans" | "vulnerabilities" | "reports";

const SECTIONS: Array<{ id: SectionId; label: string; icon: typeof BarChart3 }> = [
  { id: "dashboard", label: "Dashboard", icon: BarChart3 },
  { id: "repositories", label: "Repositories", icon: Target },
  { id: "scans", label: "Pen Test Scans", icon: Zap },
  { id: "vulnerabilities", label: "Vulnerabilities", icon: AlertCircle },
  { id: "reports", label: "Reports", icon: FileText },
];

const SECTION_META: Record<SectionId, { title: string; subtitle: string }> = {
  dashboard: { title: "Dashboard", subtitle: "Security posture across the demo repositories" },
  repositories: { title: "Repositories", subtitle: "Connected repositories and scan settings" },
  scans: { title: "Pen Test Scans", subtitle: "Scan history and execution logs" },
  vulnerabilities: { title: "Vulnerabilities", subtitle: "Findings triaged by severity" },
  reports: { title: "Reports", subtitle: "Exportable scan results" },
};

function SidebarContent({
  active,
  onSelect,
}: {
  active: SectionId;
  onSelect: (id: SectionId) => void;
}) {
  return (
    <div className="flex h-full w-60 flex-col border-r border-sidebar-border bg-sidebar">
      <div className="flex h-16 items-center gap-2 border-b border-sidebar-border px-5">
        <Shield aria-hidden className="h-6 w-6 text-accent-fg" strokeWidth={2.5} />
        <span className="text-lg font-bold text-white">PentestAI</span>
        <span className="ml-auto rounded border border-medium/40 bg-medium/15 px-1.5 py-0.5 text-[0.625rem] font-bold tracking-wide text-medium-fg uppercase">
          Demo
        </span>
      </div>

      <nav aria-label="Demo sections" className="flex-1 space-y-1 px-3 py-4">
        {SECTIONS.map((s) => {
          const isActive = active === s.id;
          return (
            <button
              key={s.id}
              onClick={() => onSelect(s.id)}
              aria-current={isActive ? "page" : undefined}
              className={`flex min-h-11 w-full cursor-pointer items-center gap-3 rounded-lg px-3 text-sm font-medium transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none ${
                isActive
                  ? "bg-primary-strong text-white"
                  : "text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-white"
              }`}
            >
              <s.icon aria-hidden className="h-4 w-4 shrink-0" />
              {s.label}
            </button>
          );
        })}
      </nav>

      <div className="border-t border-sidebar-border p-3">
        <Link
          to="/"
          className="flex min-h-11 w-full cursor-pointer items-center gap-3 rounded-lg px-3 text-sm font-medium text-sidebar-foreground/70 transition-colors hover:bg-sidebar-accent hover:text-white focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          <ArrowLeft aria-hidden className="h-4 w-4 shrink-0" />
          Back to home
        </Link>
      </div>
    </div>
  );
}

function DemoPage() {
  const [section, setSection] = useState<SectionId>("dashboard");
  const [bannerOpen, setBannerOpen] = useState(true);
  const [notifyOpen, setNotifyOpen] = useState(false);

  const notify = (message: string) => toast.message(message);
  const meta = SECTION_META[section];

  return (
    <div className="flex min-h-screen bg-background">
      <aside className="sticky top-0 hidden h-screen md:block">
        <SidebarContent active={section} onSelect={setSection} />
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 border-b border-border bg-background/80 backdrop-blur">
          <div className="flex h-16 items-center justify-between gap-4 px-4 md:px-6">
            <div className="flex min-w-0 items-center gap-3">
              <Sheet>
                <SheetTrigger asChild>
                  <Button variant="ghost" size="icon" className="md:hidden">
                    <Menu className="h-5 w-5" />
                    <span className="sr-only">Open demo navigation</span>
                  </Button>
                </SheetTrigger>
                <SheetContent side="left" className="w-60 border-sidebar-border bg-sidebar p-0">
                  <SidebarContent active={section} onSelect={setSection} />
                </SheetContent>
              </Sheet>

              <div className="min-w-0">
                <h1 className="truncate text-lg font-semibold text-foreground">{meta.title}</h1>
                <p className="truncate text-xs text-muted-foreground">{meta.subtitle}</p>
              </div>
            </div>

            <div className="flex items-center gap-2 md:gap-3">
              <span className="hidden rounded-md border border-medium/40 bg-medium/15 px-2.5 py-1 text-[0.6875rem] font-bold tracking-wide text-medium-fg uppercase sm:inline-flex">
                Demo mode
              </span>

              <button
                onClick={() => setNotifyOpen((v) => !v)}
                aria-label="Demo notifications"
                aria-expanded={notifyOpen}
                className="relative grid h-11 w-11 cursor-pointer place-items-center rounded-md transition-colors hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              >
                <Bell aria-hidden className="h-5 w-5 text-muted-foreground" />
                <span className="absolute top-1.5 right-1.5 grid h-4 min-w-4 place-items-center rounded-full bg-critical px-1 text-[0.625rem] font-bold text-white">
                  7
                </span>
              </button>

              <Button
                asChild
                size="sm"
                className="bg-primary-strong text-white hover:bg-primary-hover"
              >
                <Link to="/auth">
                  <Github aria-hidden className="mr-2 h-4 w-4" />
                  <span className="hidden sm:inline">Scan your own repo</span>
                  <span className="sm:hidden">Sign in</span>
                </Link>
              </Button>
            </div>
          </div>

          <AnimatePresence initial={false}>
            {bannerOpen && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2, ease: "easeOut" }}
                className="overflow-hidden border-t border-medium/30 bg-medium/10"
              >
                <div className="flex items-center gap-3 px-4 py-2.5 md:px-6">
                  <AlertCircle aria-hidden className="h-4 w-4 shrink-0 text-medium-fg" />
                  <p className="min-w-0 text-xs text-foreground">
                    <span className="font-semibold">
                      You&apos;re exploring a simulated environment using sample security data.
                    </span>{" "}
                    <span className="text-muted-foreground">
                      Nothing here is connected to a real repository, and no action can change real
                      data.
                    </span>
                  </p>
                  <button
                    onClick={() => setBannerOpen(false)}
                    aria-label="Dismiss demo banner"
                    className="ml-auto grid h-7 w-7 shrink-0 cursor-pointer place-items-center rounded text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                  >
                    <X aria-hidden className="h-3.5 w-3.5" />
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </header>

        <main className="flex-1 p-4 md:p-6 lg:p-8">
          <PageShell>
            {notifyOpen && (
              <div className="mb-6">
                <DemoActivity />
              </div>
            )}

            <AnimatePresence mode="wait">
              <motion.div
                key={section}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.18, ease: "easeOut" }}
              >
                {section === "dashboard" && (
                  <DemoDashboard onGoTo={(s) => setSection(s as SectionId)} />
                )}
                {section === "repositories" && <DemoRepositories onNotify={notify} />}
                {section === "scans" && <DemoScans />}
                {section === "vulnerabilities" && <DemoVulnerabilities onNotify={notify} />}
                {section === "reports" && <DemoReports onNotify={notify} />}
              </motion.div>
            </AnimatePresence>
          </PageShell>
        </main>
      </div>

      <DemoAssistant />
    </div>
  );
}
