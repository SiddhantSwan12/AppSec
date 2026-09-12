import WalletApp from "../../components/wallet-app";
export default async function Page({
  params,
}: {
  params: Promise<{ path?: string[] }>;
}) {
  const { path = [] } = await params;
  return <WalletApp key={path.join("/")} path={path.join("/")} />;
}
