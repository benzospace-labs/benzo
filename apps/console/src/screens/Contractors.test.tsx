import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Contractors } from "./Contractors";

const refreshMock = vi.hoisted(() => vi.fn(async () => true));
const navMock = vi.hoisted(() => vi.fn());

const apiMock = vi.hoisted(() => ({
  importRoster: vi.fn(),
  updateCounterparty: vi.fn(),
  contractorHistory: vi.fn(async () => []),
  createPayroll: vi.fn(),
}));

vi.mock("../lib/api", () => ({ api: apiMock }));
vi.mock("../lib/store", () => ({
  useConsole: () => ({
    counterparties: [],
    loading: false,
    refresh: refreshMock,
  }),
}));
vi.mock("react-router-dom", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useNavigate: () => navMock,
}));

describe("Contractors", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("surfaces a bad CSV row and imports nothing", async () => {
    apiMock.importRoster.mockResolvedValueOnce({
      imported: 0,
      errors: [{ line: 2, error: "Monthly USDC must be a positive number" }],
      contractors: [],
    });

    render(<Contractors />);

    fireEvent.click(screen.getByTestId("import-roster"));
    const csv = "Ava Contractor,@ava,2500\nBad Row,@bad,not-a-number";
    fireEvent.change(screen.getByTestId("import-csv"), { target: { value: csv } });
    fireEvent.click(screen.getByTestId("import-submit"));

    await waitFor(() => expect(apiMock.importRoster).toHaveBeenCalledOnce());
    expect(apiMock.importRoster).toHaveBeenCalledWith(csv);

    // The bad row is surfaced with its line number and reason...
    await waitFor(() =>
      expect(screen.getByTestId("import-errors")).toHaveTextContent("Line 2")
    );
    expect(screen.getByTestId("import-errors")).toHaveTextContent(
      "Monthly USDC must be a positive number"
    );
    // ...and the modal stays open: with errors, nothing was imported.
    expect(screen.getByTestId("import-csv")).toBeInTheDocument();
  });

  it("closes the import modal when every row imports cleanly", async () => {
    apiMock.importRoster.mockResolvedValueOnce({
      imported: 2,
      errors: [],
      contractors: [],
    });

    render(<Contractors />);

    fireEvent.click(screen.getByTestId("import-roster"));
    fireEvent.change(screen.getByTestId("import-csv"), {
      target: { value: "Ava Contractor,@ava,2500\nBo Chen,@bo,3200" },
    });
    fireEvent.click(screen.getByTestId("import-submit"));

    await waitFor(() => expect(apiMock.importRoster).toHaveBeenCalledOnce());
    // Clean import: the modal closes (the form is gone).
    await waitFor(() =>
      expect(screen.queryByTestId("import-csv")).not.toBeInTheDocument()
    );
  });
});
