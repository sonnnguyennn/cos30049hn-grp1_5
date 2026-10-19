import Link from "next/link";
import Logo from "../logo";
import NavLinks from "./nav-links";

export default function SideNav() {
  return (
    <div className="m-4 flex flex-col rounded-2xl bg-[#ffffff] py-1 md:flex-1">
        <Link className="flex h-25 items-center justify-center" href="/dashboard">
            <div className="flex">
                <Logo />
            </div>
        </Link>
        <div className="flex flex-col gap-2" >
          <NavLinks/>
        </div>
    </div>
  );
}
