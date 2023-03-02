package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ListThread extends Thread{

    LinkedList<Integer> blackListOcurrences;
    String ipaddress;

    int a;

    int b;

    //skds.getRegisteredServersCount()

    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());

    private static final int BLACK_LIST_ALARM_COUNT=5;

    public ListThread(String ipaddress, int a, int b,LinkedList<Integer> blackListOcurrences){
        this.ipaddress = ipaddress;
        this.a = a;
        this.b = b;
        this.blackListOcurrences = blackListOcurrences;
    }


    @Override
    public void run(){
        checkHost();
    }

    public List<Integer> checkHost(){

        int ocurrencesCount=0;

        HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();

        int checkedListsCount=0;

        for (int i=a;i< b && ocurrencesCount<BLACK_LIST_ALARM_COUNT;i++){
            checkedListsCount++;

            if (skds.isInBlackListServer(i, ipaddress)){

                blackListOcurrences.add(i);

                ocurrencesCount++;
            }
        }

        if (ocurrencesCount>=BLACK_LIST_ALARM_COUNT){
            skds.reportAsNotTrustworthy(ipaddress);
        }
        else{
            skds.reportAsTrustworthy(ipaddress);
        }

        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{checkedListsCount, skds.getRegisteredServersCount()});

        return blackListOcurrences;
    }

    public synchronized LinkedList<Integer> getBlackListOcurrences() {
        return blackListOcurrences;
    }
}
