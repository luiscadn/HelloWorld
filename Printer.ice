module Demo {
  struct Response {
    long responseTime; // ms
    string value;
  };

  interface Printer {
    Response printString(string s);
  };
};
