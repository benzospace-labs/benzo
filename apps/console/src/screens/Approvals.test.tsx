import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Member, PaymentOrder } from "@benzo/types";
import { ToastProvider } from "../ui/controls";
import { Approvals } from "./Approvals";

const refreshMock = vi.hoisted(() => vi.fn(async () => true));

const apiMock = vi.hoisted(() => ({
  approvePayment: vi.fn(),
}));

const storeBox = vi.hoisted(() => ({
  payments: [] as PaymentOrder[],
  members: [] as Member[],
}));

vi.mock("../lib/api", () => ({ api: apiMock }));
vi.mock("../lib/store", () => ({
  useConsole: () => ({
    payments: storeBox.payments,
    members: storeBox.members,
    masked: false,
    refresh: refreshMock,
    loading: false,
  }),
  useCounterpartyName: () => (id?: string) => "Ava Contractor",
}));

function makePayment(): PaymentOrder {
  return {
    id: "pay_1",
    orgId: "org_test",
    type: "shielded_transfer",
    status: "needs_approval",
    amount: { amount: "50000000", assetCode: "USDC" },
    fromAccountId: "acct_treasury",
    toCounterpartyId: "cp_1",
    memo: "June contractor payout",
    approvals: [],
    privacy: { amountHidden: false, counterpartyHidden: false, visibleTo: [] },
    settlement: {},
    createdByMemberId: "m_owner",
    createdAt: "2026-06-26T00:00:00.000Z",
    updatedAt: "2026-06-26T00:00:00.000Z",
  } as PaymentOrder;
}

function makeMembers(): Member[] {
  return [
    { id: "m_owner", orgId: "org_test", email: "owner@benzo.test", name: "Owen", role: "owner", status: "active" },
    { id: "m_treasurer", orgId: "org_test", email: "treasurer@benzo.test", name: "Tara", role: "treasurer", status: "active" },
  ] as Member[];
}

function renderApprovals() {
  return render(
    <ToastProvider>
      <Approvals />
    </ToastProvider>
  );
}

describe("Approvals", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    storeBox.members = makeMembers();
    storeBox.payments = [makePayment()];
  });

  it("refuses to release when the quorum is unmet", async () => {
    // One approval recorded, but the policy needs a second approver:
    // the quorum gate is not satisfied.
    apiMock.approvePayment.mockResolvedValueOnce({
      ...makePayment(),
      progress: {
        required: true,
        satisfied: false,
        nextRole: "treasurer",
        nextKind: "approve",
        steps: [],
      },
    });

    renderApprovals();

    fireEvent.click(screen.getByTestId("approve-btn"));

    await waitFor(() => expect(apiMock.approvePayment).toHaveBeenCalledOnce());
    expect(apiMock.approvePayment).toHaveBeenCalledWith("pay_1", { decision: "approved" });

    // The screen reports the missing approver...
    await waitFor(() =>
      expect(screen.getByText("Approved · now needs treasurer")).toBeInTheDocument()
    );
    // ...and never claims the payment was released.
    expect(screen.queryByText("Released and paid")).not.toBeInTheDocument();
  });

  it("releases only once the quorum is satisfied", async () => {
    apiMock.approvePayment.mockResolvedValueOnce({
      ...makePayment(),
      progress: {
        required: true,
        satisfied: true,
        nextRole: null,
        nextKind: null,
        steps: [],
      },
      settlement: { onChain: true, txHash: "abc123" },
    });

    renderApprovals();

    fireEvent.click(screen.getByTestId("approve-btn"));

    await waitFor(() => expect(apiMock.approvePayment).toHaveBeenCalledOnce());
    await waitFor(() =>
      expect(screen.getByText("Released and paid")).toBeInTheDocument()
    );
  });
});
