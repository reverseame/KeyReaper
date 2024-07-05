#ifndef KEYSCANNER_H
#define KEYSCANNER_H

class KeyScanner {
 private:
  int windowSize;
  list keys;
  DWORD pid;

 public:
  void structureScan();

  void roundKeyScan();

  void entropyScan();

  void yaraScan();

 private:
  /**
   * Internal method for the scanner methods to add keys to the object
   */
  void addKeys(keys list);

 public:
  list getKeys();

  void killProcess();

  void pauseProcess();

  void resumeProcess();

  KeyScanner(int pid);

  void DestroyAndKill();

  void DestroyAndResume();

  void DestroyAndKeepPaused();
};

#endif
