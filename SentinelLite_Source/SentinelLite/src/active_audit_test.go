package main

import("testing";"time";"fmt")

func TestActiveAuditHistoryRetentionAndOmissions(t *testing.T) {
    m:=newActiveMonitor(nil)
    for i:=0;i<320;i++{
        m.mu.Lock()
        m.appendEventLocked(ActiveEvent{At:time.Now(),Path:fmt.Sprintf("sample%d.txt",i),Action:"clean"})
        m.mu.Unlock()
    }
    for i:=0;i<130;i++{
        m.logLaunchEvent(ActiveEvent{At:time.Now(),Path:fmt.Sprintf("launch%d.exe",i),Action:"launch-denied"})
    }
    st:=m.snapshot()
    if len(st.Events)!=300||st.EventsOmitted!=150 {
        t.Fatalf("main history overflow not accounted for: len=%d omitted=%d",len(st.Events),st.EventsOmitted)
    }
    if len(st.LaunchEvents)!=120||st.LaunchEventsOmitted!=10 {
        t.Fatalf("launch history overflow not accounted for: len=%d omitted=%d",len(st.LaunchEvents),st.LaunchEventsOmitted)
    }
    m.clearHistory()
    st=m.snapshot()
    if st.EventsOmitted!=0||st.LaunchEventsOmitted!=0||len(st.LaunchEvents)>0 {
        t.Fatal("clear-history must reset overflow accounting")
    }
}
