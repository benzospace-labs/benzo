import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { PayrollBatch } from "@benzo/types";
import { Payroll } from "./Payroll";

const refreshMock = vi.hoisted(() => vi.fn(async () => true));

const storeBox = vi.hoisted(() => ({ payrolls: [] as PayrollBatch[] }));

vi.mock("../lib/api", () => ({ api: {} }));
vi.mock("../lib/store", () => ({
  useConsole: () => ({
    payrolls: storeBox.payrolls,
    counterparties: [],
    masked: false,
    refresh: refreshMock,
    loading: false,
  }),
  useCounterpartyName: () => (id?: string) => id ?? "Unknown",
}));

function makeBatch(totalStroops: string): PayrollBatch {
  return {
    id: "pb_1",
    orgId: "org_test",
    period: "2026-06",
    source: "manual",
    status: "approved",
    lines: [{ counterpartyId: "cp_1", amount: totalStroops, rate: totalStroops, status: "pending" }],
    total: { amount: totalStroops, assetCode: "USDC" },
    createdAt: "2026-06-26T00:00:00.000Z",
  } as PayrollBatch;
}

describe("Payroll", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // One contractor on a $2.00/mo rate card; the server computed the run
    // total from that card: 20_000_000 stroops @ 7 decimals.
    storeBox.payrolls = [makeBatch("20000000")];
  });

  it("shows the server-computed run total", () => {
    render(<Payroll />);
    expect(screen.getByTestId("payroll-total")).toHaveTextContent("$2.00");
  });

  it("recomputes the displayed total when the rate card changes", () => {
    const { rerender } = render(<Payroll />);
    expect(screen.getByTestId("payroll-total")).toHaveTextContent("$2.00");

    // The contractor's rate card was edited in the roster, the server
    // recomputed the run from the new card ($3.50/mo), and the store
    // refresh delivered the new total. The screen must show the
    // recomputed value, not the stale one.
    storeBox.payrolls = [makeBatch("35000000")];
    rerender(<Payroll />);

    expect(screen.getByTestId("payroll-total")).toHaveTextContent("$3.50");
  });
});
