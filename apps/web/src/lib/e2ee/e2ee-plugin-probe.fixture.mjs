export let capturedContext = null;

export default {
  activate(context) {
    capturedContext = context;
  },
  deactivate() {
    capturedContext = null;
  },
};
