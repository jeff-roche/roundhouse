import { render } from "solid-js/web";

import { App } from "./App";
import { bootToken } from "./token";

// Must run synchronously, before `render()`: the pairing token has to leave
// the URL before anything else touches history — including Solid's own
// router, once slice B adds one. See `token.ts` for the whole contract.
bootToken();

const container = document.getElementById("app");
if (container === null) {
  throw new Error("index.html is missing the #app mount point");
}

render(() => <App />, container);
