"""Bounded capture-local TCP byte reconstruction; payload never leaves memory.

Private derived hashes are for independent qualification, not MCP disclosure.
TCP endpoint overlap policy, delivery, full capture and causality stay unknown.
"""
from array import array
import hashlib

MAX_STREAMS=16
MAX_BYTES=65536
MAX_SEGMENTS=256
MAX_RANGES=16
MAX_PROVENANCE=32


class Stream:
    def __init__(self,flow_id,epoch,seq,flags,frame):
        self.flow_id=flow_id;self.epoch=epoch
        self.syn=bool(flags&2);self.isn=seq if self.syn else None
        self.base=(seq+int(self.syn))&0xffffffff
        self.first_frame=frame;self.last_frame=frame
        self.data=bytearray(MAX_BYTES);self.present=bytearray(MAX_BYTES)
        self.frames=array('I',[0])*MAX_BYTES
        self.segments=0;self.overlap_bytes=0;self.conflicting_bytes=0
        self.fin_end=None;self.fin_frame=None;self.limits=set();self.truncated_frames=0

    def observe(self,seq,flags,payload,frame,truncated):
        self.last_frame=frame;self.segments+=1
        if truncated:self.truncated_frames+=1
        if self.segments>MAX_SEGMENTS:self.limits.add('segment_budget');return
        start=((seq+int(bool(flags&2)))-self.base)&0xffffffff
        if start>=0x80000000:
            # Without a captured SYN, earlier out-of-order data can shift the
            # bounded observed range. No beginning-of-stream claim is made.
            shift=(self.base-(seq+int(bool(flags&2))))&0xffffffff
            high=max(max((i+1 for i,v in enumerate(self.present) if v),default=0),self.fin_end or 0)
            if self.syn or shift>MAX_BYTES or high+shift>MAX_BYTES:
                self.limits.add('sequence_outside_window');return
            self.data[shift:]=self.data[:MAX_BYTES-shift]
            self.present[shift:]=self.present[:MAX_BYTES-shift]
            self.frames[shift:]=self.frames[:MAX_BYTES-shift]
            self.data[:shift]=b'\0'*shift;self.present[:shift]=b'\0'*shift;self.frames[:shift]=array('I',[0])*shift
            self.base=(self.base-shift)&0xffffffff
            if self.fin_end is not None:self.fin_end+=shift
            start=0
        if start+len(payload)>MAX_BYTES:
            self.limits.add('byte_window_budget');return
        if flags&1:
            end=start+len(payload)
            if self.fin_end is not None and self.fin_end!=end:self.limits.add('conflicting_fin')
            else:self.fin_end=end;self.fin_frame=frame
        for offset,value in enumerate(payload,start):
            if self.present[offset]:
                self.overlap_bytes+=1
                if self.data[offset]!=value:self.conflicting_bytes+=1
            else:
                self.data[offset]=value;self.present[offset]=1;self.frames[offset]=frame

    def summary(self):
        high=max((i+1 for i,v in enumerate(self.present) if v),default=0)
        extent=max(high,self.fin_end or 0)
        ranges=[];holes=[];start=0
        while start<extent:
            present=bool(self.present[start]);end=start+1
            while end<extent and bool(self.present[end])==present:end+=1
            (ranges if present else holes).append({'start':start,'end':end})
            start=end
        frames=sorted(set(self.frames)-{0})
        reconstructed=bool(extent) and not holes and not self.conflicting_bytes and not self.limits and not self.truncated_frames
        complete_range=reconstructed and self.syn and self.fin_end==extent
        return {'flow_id':self.flow_id,'epoch':self.epoch,'first_frame':self.first_frame,'last_frame':self.last_frame,
            'captured_syn':self.syn,'captured_fin':self.fin_end is not None,'fin_frame':self.fin_frame,'fin_relative_end':self.fin_end,
            'observed_extent_bytes':extent,'unique_payload_bytes':sum(self.present),'segments_examined':self.segments,
            'overlap_byte_observations':self.overlap_bytes,'conflicting_byte_observations':self.conflicting_bytes,
            'truncated_frames':self.truncated_frames,'limits':sorted(self.limits),
            'observed_ranges':ranges[:MAX_RANGES],'observed_ranges_omitted':max(0,len(ranges)-MAX_RANGES),
            'unobserved_ranges':holes[:MAX_RANGES],'unobserved_ranges_omitted':max(0,len(holes)-MAX_RANGES),
            'contributing_frames':frames[:MAX_PROVENANCE],'contributing_frames_omitted':max(0,len(frames)-MAX_PROVENANCE),
            'contiguous_observed_range_reconstructed':reconstructed,
            'syn_to_fin_payload_covered':complete_range,
            'private_contiguous_sha256':hashlib.sha256(self.data[:extent]).hexdigest() if reconstructed else None}


class StreamTracker:
    def __init__(self):self.current={};self.streams=[];self.omitted_segments=0

    def observe(self,flow_id,seq,flags,payload,frame,truncated=False):
        stream=self.current.get(flow_id)
        if stream is None or flags&2 and (not stream.syn or stream.isn!=seq):
            if len(self.streams)>=MAX_STREAMS:
                self.omitted_segments+=1
                if stream is not None:
                    stream.limits.add('later_epoch_omitted')
                    self.current.pop(flow_id,None)
                return
            epoch=stream.epoch+1 if stream else 1
            stream=Stream(flow_id,epoch,seq,flags,frame)
            self.current[flow_id]=stream;self.streams.append(stream)
        stream.observe(seq,flags,payload,frame,truncated)

    def summary(self):
        return {'schema':1,'streams':[s.summary() for s in self.streams],
            'omitted_segments':self.omitted_segments,'maximum_streams':MAX_STREAMS,
            'maximum_bytes_per_stream':MAX_BYTES,'maximum_segments_per_stream':MAX_SEGMENTS,
            'policy':'FIRST_CAPTURED_BYTE; conflicting overlaps are ambiguous; no endpoint policy inferred',
            'packet_loss_proven':False,'endpoint_delivery_proven':False,'capture_complete':False}
